use std::{
    collections::HashMap,
    net::SocketAddr,
    os::unix::process::ExitStatusExt,
    panic::AssertUnwindSafe,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime},
};

use futures_util::FutureExt;
use thiserror::Error;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::{Notify, broadcast, mpsc, oneshot, watch},
    task::JoinHandle,
    time::{Instant, sleep_until},
};

use crate::{
    audit::{
        AuditCloseReason, AuditEvent, AuditLog, AuditOutcome, AuditTimestamp, CorrelationId,
        DenialCategory, DenialReason, ResolvedAuditTarget, SessionId,
    },
    config::{Limits, PtyTarget, Target, TargetAllowlist},
    protocol::{self, MAX_BINARY_BYTES, Resize},
    pty_backend::{BackendError, PtyProcessBackend, RunningPty, RunningSsh},
    ssh::{
        PreparedSshTargets, SshClientLog, SshDiagnosticClass, SshDiagnosticClassifier,
        SshSpawnError, SshSpawnSpec,
    },
    ticket::Identity,
};

const INPUT_CHANNEL_CAPACITY: usize = 8;
const OUTPUT_CHANNEL_CAPACITY: usize = 8;
const LIFECYCLE_CHANNEL_CAPACITY: usize = 3;
const AUDIT_CHANNEL_CAPACITY: usize = 64;
const CLEANUP_GRACE: Duration = Duration::from_millis(150);
const CLEANUP_RETRY_DELAY: Duration = Duration::from_millis(25);
const CHILD_EXIT_SETTLE: Duration = Duration::from_millis(250);
const WORKER_JOIN_TIMEOUT: Duration = Duration::from_secs(1);
const SSH_ADMISSION_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    Created,
    Running,
    Closed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimeoutKind {
    Idle,
    Absolute,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionCloseReason {
    ChildExited,
    Explicit,
    TransportDropped,
    ProtocolViolation,
    PolicyViolation,
    InternalFailure,
    HandleDropped,
    SupervisorUnwind,
    ManagerShutdown,
    Timeout(TimeoutKind),
    BackendFailure,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChildOutcome {
    Code(u8),
    Signal(u8),
    Unavailable,
}

impl ChildOutcome {
    fn from_status(status: std::process::ExitStatus) -> Self {
        if let Some(code) = status.code().and_then(|code| u8::try_from(code).ok()) {
            Self::Code(code)
        } else if let Some(signal) = status.signal().and_then(|signal| u8::try_from(signal).ok()) {
            Self::Signal(signal)
        } else {
            Self::Unavailable
        }
    }

    pub fn as_protocol(self) -> protocol::ExitStatus {
        match self {
            Self::Code(code) => protocol::ExitStatus::Code(code),
            Self::Signal(signal) if (1..=127).contains(&signal) => {
                protocol::ExitStatus::Signal(signal)
            }
            Self::Signal(_) | Self::Unavailable => protocol::ExitStatus::Unavailable,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LifecycleTransition {
    Created,
    Running,
    Closed {
        reason: SessionCloseReason,
        outcome: Option<ChildOutcome>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LifecycleEvent {
    pub identity: Identity,
    pub target: String,
    pub at: SystemTime,
    pub transition: LifecycleTransition,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum SessionError {
    #[error("The global session limit has been reached.")]
    GlobalLimit,
    #[error("The identity session limit has been reached.")]
    IdentityLimit,
    #[error("The configured terminal could not be started.")]
    SpawnUnavailable,
    #[error("The requested terminal target is unavailable.")]
    TargetUnavailable,
    #[error("The terminal session manager is shutting down.")]
    ManagerClosed,
    #[error("The session reservation is unavailable.")]
    ReservationUnavailable,
    #[error("The terminal backend is unavailable.")]
    BackendUnavailable,
    #[error("The required audit control is unavailable.")]
    AuditUnavailable,
    #[error("The SSH host identity could not be verified.")]
    SshHostKeyFailed,
    #[error("The SSH connection could not be established.")]
    SshConnectionFailed,
    #[error("SSH authentication was rejected.")]
    SshAuthenticationFailed,
    #[error("The SSH user policy denied the session.")]
    SshPolicyDenied,
    #[error("The SSH session could not be established safely.")]
    SshFailed,
    #[error("The terminal session is closed.")]
    Closed,
    #[error("The configured terminal is read-only.")]
    ReadOnly,
    #[error("The terminal input is too large.")]
    InputTooLarge,
    #[error("The terminal dimensions are invalid.")]
    InvalidResize,
    #[error("The session state transition is invalid.")]
    InvalidTransition,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionClosed {
    pub state: SessionState,
    pub reason: SessionCloseReason,
    pub outcome: Option<ChildOutcome>,
}

#[derive(Debug)]
struct StateMachine {
    state: SessionState,
    terminal: Option<SessionClosed>,
}

impl StateMachine {
    fn new() -> Self {
        Self {
            state: SessionState::Created,
            terminal: None,
        }
    }

    #[cfg(test)]
    fn state(&self) -> SessionState {
        self.state
    }

    fn start(&mut self) -> Result<SessionState, SessionError> {
        if self.state != SessionState::Created {
            return Err(SessionError::InvalidTransition);
        }
        self.state = SessionState::Running;
        Ok(self.state)
    }

    fn close(
        &mut self,
        reason: SessionCloseReason,
        outcome: Option<ChildOutcome>,
    ) -> Result<SessionClosed, SessionError> {
        if let Some(terminal) = self.terminal {
            return Ok(terminal);
        }
        if self.state != SessionState::Running {
            return Err(SessionError::InvalidTransition);
        }
        let terminal = SessionClosed {
            state: SessionState::Closed,
            reason,
            outcome,
        };
        self.state = SessionState::Closed;
        self.terminal = Some(terminal);
        Ok(terminal)
    }
}

#[derive(Debug)]
struct Capacity {
    inner: Arc<CapacityInner>,
}

#[derive(Debug)]
struct CapacityInner {
    max_sessions: usize,
    max_sessions_per_identity: usize,
    state: Mutex<CapacityState>,
    clock: Arc<dyn CapacityClock>,
}

#[derive(Debug, Default)]
struct CapacityState {
    next_id: u64,
    closed: bool,
    leases: HashMap<u64, Lease>,
}

#[derive(Debug)]
struct Lease {
    identity: Identity,
    state: LeaseState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LeaseState {
    Pending { expires_at: Instant },
    Live,
}

trait CapacityClock: Send + Sync + std::fmt::Debug {
    fn now(&self) -> Instant;
}

#[derive(Debug)]
struct SystemCapacityClock;

impl CapacityClock for SystemCapacityClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
}

impl Capacity {
    fn new(limits: &Limits) -> Self {
        Self::with_clock(limits, Arc::new(SystemCapacityClock))
    }

    fn with_clock(limits: &Limits, clock: Arc<dyn CapacityClock>) -> Self {
        Self {
            inner: Arc::new(CapacityInner {
                max_sessions: limits.max_sessions,
                max_sessions_per_identity: limits.max_sessions_per_user,
                state: Mutex::new(CapacityState::default()),
                clock,
            }),
        }
    }

    fn reserve(&self, identity: &Identity) -> Result<Reservation, SessionError> {
        self.reserve_with_state(identity, LeaseState::Live)
    }

    fn reserve_pending(
        &self,
        identity: &Identity,
        expires_at: Instant,
    ) -> Result<Reservation, SessionError> {
        if expires_at <= self.inner.clock.now() {
            return Err(SessionError::ReservationUnavailable);
        }
        self.reserve_with_state(identity, LeaseState::Pending { expires_at })
    }

    fn reserve_with_state(
        &self,
        identity: &Identity,
        lease_state: LeaseState,
    ) -> Result<Reservation, SessionError> {
        let mut state = self
            .inner
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let now = self.inner.clock.now();
        purge_expired_leases(&mut state, now);
        if matches!(
            lease_state,
            LeaseState::Pending { expires_at } if expires_at <= now
        ) {
            return Err(SessionError::ReservationUnavailable);
        }
        if state.closed {
            return Err(SessionError::ManagerClosed);
        }
        if state.leases.len() >= self.inner.max_sessions {
            return Err(SessionError::GlobalLimit);
        }
        let identity_count = state
            .leases
            .values()
            .filter(|lease| &lease.identity == identity)
            .count();
        if identity_count >= self.inner.max_sessions_per_identity {
            return Err(SessionError::IdentityLimit);
        }
        let id = state.next_id;
        state.next_id = state.next_id.wrapping_add(1);
        state.leases.insert(
            id,
            Lease {
                identity: identity.clone(),
                state: lease_state,
            },
        );
        Ok(Reservation {
            capacity: Arc::clone(&self.inner),
            id: Some(id),
        })
    }

    #[cfg(test)]
    fn active(&self) -> (usize, usize) {
        let mut state = self
            .inner
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        purge_expired_leases(&mut state, self.inner.clock.now());
        let mut by_identity = HashMap::<Identity, usize>::new();
        for lease in state.leases.values() {
            *by_identity.entry(lease.identity.clone()).or_default() += 1;
        }
        (
            state.leases.len(),
            by_identity.values().copied().max().unwrap_or(0),
        )
    }

    fn close_pending(&self) {
        let mut state = self
            .inner
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.closed = true;
        state
            .leases
            .retain(|_, lease| lease.state == LeaseState::Live);
    }
}

fn purge_expired_leases(state: &mut CapacityState, now: Instant) {
    state.leases.retain(|_, lease| {
        !matches!(
            lease.state,
            LeaseState::Pending { expires_at } if expires_at <= now
        )
    });
}

#[derive(Debug)]
struct Reservation {
    capacity: Arc<CapacityInner>,
    id: Option<u64>,
}

impl Reservation {
    fn activate(self, identity: &Identity) -> Result<Self, SessionError> {
        let Some(id) = self.id else {
            return Err(SessionError::ReservationUnavailable);
        };
        let mut state = self
            .capacity
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        purge_expired_leases(&mut state, self.capacity.clock.now());
        if state.closed {
            return Err(SessionError::ManagerClosed);
        }
        let lease = state
            .leases
            .get_mut(&id)
            .ok_or(SessionError::ReservationUnavailable)?;
        if &lease.identity != identity || lease.state == LeaseState::Live {
            return Err(SessionError::ReservationUnavailable);
        }
        lease.state = LeaseState::Live;
        drop(state);
        Ok(self)
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        let Some(id) = self.id.take() else {
            return;
        };
        self.capacity
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .leases
            .remove(&id);
    }
}

#[derive(Debug)]
pub struct SessionReservation {
    inner: Reservation,
}

impl SessionReservation {
    fn activate(self, identity: &Identity) -> Result<Reservation, SessionError> {
        self.inner.activate(identity)
    }

    #[cfg(test)]
    pub(crate) fn test_reservation(identity: &Identity) -> Self {
        Capacity::new(&Limits {
            max_sessions: 1,
            max_sessions_per_user: 1,
            idle_timeout: Duration::from_secs(60),
            absolute_timeout: Duration::from_secs(600),
            session_requests_per_window: 10,
            session_request_window: Duration::from_secs(60),
            authentication_failures_per_window: 20,
            authentication_failure_window: Duration::from_secs(60),
        })
        .reserve_session(identity, Instant::now() + Duration::from_secs(60))
        .expect("test capacity permits one reservation")
    }
}

impl Capacity {
    fn reserve_session(
        &self,
        identity: &Identity,
        expires_at: Instant,
    ) -> Result<SessionReservation, SessionError> {
        self.reserve_pending(identity, expires_at)
            .map(|inner| SessionReservation { inner })
    }
}

enum BackendSpawn {
    Pty(PtyTarget),
    Ssh {
        spec: Box<SshSpawnSpec>,
        classifier: SshDiagnosticClassifier,
    },
}

struct BackendStart {
    target_name: String,
    read_only: bool,
    spawn: BackendSpawn,
}

enum SpawnedBackend {
    Pty(RunningPty),
    Ssh(RunningSsh, SshDiagnosticClassifier),
    #[cfg(test)]
    TestSsh(RunningPty, mpsc::UnboundedReceiver<SshDiagnosticClass>),
}

trait Backend: Send + Sync {
    fn spawn(&self, target: BackendSpawn, size: Resize) -> Result<SpawnedBackend, BackendError>;
}

impl Backend for PtyProcessBackend {
    fn spawn(&self, target: BackendSpawn, size: Resize) -> Result<SpawnedBackend, BackendError> {
        match target {
            BackendSpawn::Pty(target) => Self::spawn(&target, size).map(SpawnedBackend::Pty),
            BackendSpawn::Ssh { spec, classifier } => crate::ssh::spawn(*spec, size).map_or_else(
                |_| Err(BackendError::Unavailable),
                |running| Ok(SpawnedBackend::Ssh(running, classifier)),
            ),
        }
    }
}

#[derive(Clone)]
pub struct SessionManager {
    limits: Limits,
    capacity: Arc<Capacity>,
    backend: Arc<dyn Backend>,
    targets: Arc<TargetAllowlist>,
    prepared_ssh: Arc<PreparedSshTargets>,
    supervisors: Arc<SupervisorRegistry>,
    audit_tx: broadcast::Sender<LifecycleEvent>,
    audit: Option<Arc<AuditLog>>,
    #[cfg(test)]
    panic_supervisor_for_test: bool,
    #[cfg(test)]
    connecting_panic_for_test: Option<ConnectingPanicPoint>,
}

#[cfg(test)]
#[derive(Clone, Copy, PartialEq, Eq)]
enum ConnectingPanicPoint {
    BeforeAdmission,
    AfterAuditStart,
    AfterHandoffTake,
}

#[derive(Default)]
struct SupervisorRegistry {
    inner: Mutex<SupervisorRegistryState>,
    admission: tokio::sync::RwLock<()>,
    shutdown: tokio::sync::Mutex<()>,
    completed: Notify,
}

#[derive(Default)]
struct SupervisorRegistryState {
    next_id: u64,
    shutting_down: bool,
    active: HashMap<u64, ActiveSupervisor>,
}

struct ActiveSupervisor {
    close_tx: watch::Sender<Option<SessionCloseReason>>,
    _task: JoinHandle<()>,
}

struct SupervisorCompletion {
    registry: Arc<SupervisorRegistry>,
    id: u64,
}

impl Drop for SupervisorCompletion {
    fn drop(&mut self) {
        self.registry
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .active
            .remove(&self.id);
        self.registry.completed.notify_one();
    }
}

impl std::fmt::Debug for SessionManager {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SessionManager")
            .field("limits", &self.limits)
            .finish_non_exhaustive()
    }
}

impl SessionManager {
    pub fn new(limits: Limits, targets: TargetAllowlist) -> Self {
        Self::build(limits, targets, None)
    }

    pub fn new_with_audit(limits: Limits, targets: TargetAllowlist, audit: Arc<AuditLog>) -> Self {
        Self::build(limits, targets, Some(audit))
    }

    fn build(limits: Limits, targets: TargetAllowlist, audit: Option<Arc<AuditLog>>) -> Self {
        let (audit_tx, _) = broadcast::channel(AUDIT_CHANNEL_CAPACITY);
        Self {
            capacity: Arc::new(Capacity::new(&limits)),
            limits,
            backend: Arc::new(PtyProcessBackend),
            targets: Arc::new(targets),
            prepared_ssh: Arc::new(PreparedSshTargets::default()),
            supervisors: Arc::new(SupervisorRegistry::default()),
            audit_tx,
            audit,
            #[cfg(test)]
            panic_supervisor_for_test: false,
            #[cfg(test)]
            connecting_panic_for_test: None,
        }
    }

    pub(crate) fn with_prepared_ssh(mut self, prepared_ssh: Arc<PreparedSshTargets>) -> Self {
        self.prepared_ssh = prepared_ssh;
        self
    }

    #[cfg(test)]
    fn with_supervisor_panic_for_test(mut self) -> Self {
        self.panic_supervisor_for_test = true;
        self
    }

    #[cfg(test)]
    fn with_connecting_panic_for_test(mut self, point: ConnectingPanicPoint) -> Self {
        self.connecting_panic_for_test = Some(point);
        self
    }

    pub fn subscribe_events(&self) -> broadcast::Receiver<LifecycleEvent> {
        self.audit_tx.subscribe()
    }

    #[cfg(test)]
    fn supervisor_count_for_test(&self) -> usize {
        self.supervisors
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .active
            .len()
    }

    pub async fn start(
        &self,
        identity: Identity,
        target_name: &str,
        initial_size: Resize,
    ) -> Result<Session, SessionError> {
        self.start_with_remote(identity, target_name, initial_size, None)
            .await
    }

    pub async fn start_with_remote(
        &self,
        identity: Identity,
        target_name: &str,
        initial_size: Resize,
        remote_address: Option<SocketAddr>,
    ) -> Result<Session, SessionError> {
        let admission = self.supervisors.admission.read().await;
        if self
            .supervisors
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .shutting_down
        {
            return Err(SessionError::ManagerClosed);
        }
        validate_resize(&initial_size)?;
        let reservation = self.capacity.reserve(&identity)?;
        let target = match self.resolve_backend_target(&identity, target_name) {
            Ok(target) => target,
            Err(error) => {
                if self
                    .record_backend_resolution_denial(&identity, target_name, remote_address, error)
                    .is_err()
                {
                    return Err(SessionError::AuditUnavailable);
                }
                return Err(error);
            }
        };
        self.start_admitted(
            admission,
            identity,
            target,
            initial_size,
            reservation,
            remote_address,
        )
        .await
    }

    pub async fn reserve(
        &self,
        identity: &Identity,
        expires_at: Instant,
    ) -> Result<SessionReservation, SessionError> {
        let _admission = self.supervisors.admission.read().await;
        if self
            .supervisors
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .shutting_down
        {
            return Err(SessionError::ManagerClosed);
        }
        self.capacity.reserve_session(identity, expires_at)
    }

    pub async fn start_reserved(
        &self,
        reservation: SessionReservation,
        identity: Identity,
        target_name: &str,
        initial_size: Resize,
    ) -> Result<Session, SessionError> {
        self.start_reserved_with_remote(reservation, identity, target_name, initial_size, None)
            .await
    }

    pub async fn start_reserved_with_remote(
        &self,
        reservation: SessionReservation,
        identity: Identity,
        target_name: &str,
        initial_size: Resize,
        remote_address: Option<SocketAddr>,
    ) -> Result<Session, SessionError> {
        let admission = self.supervisors.admission.read().await;
        if self
            .supervisors
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .shutting_down
        {
            return Err(SessionError::ManagerClosed);
        }
        validate_resize(&initial_size)?;
        let reservation = reservation.activate(&identity)?;
        let target = match self.resolve_backend_target(&identity, target_name) {
            Ok(target) => target,
            Err(error) => {
                if self
                    .record_backend_resolution_denial(&identity, target_name, remote_address, error)
                    .is_err()
                {
                    return Err(SessionError::AuditUnavailable);
                }
                return Err(error);
            }
        };
        self.start_admitted(
            admission,
            identity,
            target,
            initial_size,
            reservation,
            remote_address,
        )
        .await
    }

    fn resolve_backend_target(
        &self,
        identity: &Identity,
        target_name: &str,
    ) -> Result<BackendStart, SessionError> {
        match self.targets.resolve(target_name) {
            Ok(Target::Pty(target)) => Ok(BackendStart {
                target_name: target.name.clone(),
                read_only: target.read_only,
                spawn: BackendSpawn::Pty(target.clone()),
            }),
            Ok(Target::Ssh(_)) => {
                let prepared = self
                    .prepared_ssh
                    .get(target_name)
                    .ok_or(SessionError::TargetUnavailable)?;
                let classifier = prepared.diagnostic_classifier();
                let spec =
                    SshSpawnSpec::build(prepared, identity.as_str()).map_err(
                        |error| match error {
                            SshSpawnError::PolicyDenied => SessionError::SshPolicyDenied,
                            SshSpawnError::AuthorityUnavailable
                            | SshSpawnError::MaterialChanged
                            | SshSpawnError::BackendUnavailable => SessionError::SpawnUnavailable,
                        },
                    )?;
                Ok(BackendStart {
                    target_name: prepared.name().to_owned(),
                    read_only: prepared.read_only(),
                    spawn: BackendSpawn::Ssh {
                        spec: Box::new(spec),
                        classifier,
                    },
                })
            }
            Err(_) => Err(SessionError::TargetUnavailable),
        }
    }

    async fn start_admitted(
        &self,
        admission: tokio::sync::RwLockReadGuard<'_, ()>,
        identity: Identity,
        target: BackendStart,
        initial_size: Resize,
        reservation: Reservation,
        remote_address: Option<SocketAddr>,
    ) -> Result<Session, SessionError> {
        let BackendStart {
            target_name,
            read_only,
            spawn,
        } = target;
        let running = match self.backend.spawn(spawn, initial_size) {
            Ok(running) => running,
            Err(_) => {
                if self
                    .record_denial(
                        &identity,
                        &target_name,
                        remote_address,
                        DenialCategory::Target,
                        DenialReason::SessionUnavailable,
                    )
                    .is_err()
                {
                    return Err(SessionError::AuditUnavailable);
                }
                return Err(SessionError::SpawnUnavailable);
            }
        };
        let (command_tx, command_rx) = mpsc::channel(INPUT_CHANNEL_CAPACITY);
        let (output_tx, output_rx) = mpsc::channel(OUTPUT_CHANNEL_CAPACITY);
        let (close_tx, close_rx) = watch::channel(None);
        let (cancel_tx, cancel_rx) = watch::channel(false);
        let (activity_tx, activity_rx) = watch::channel(Instant::now());
        let (final_tx, final_rx) = watch::channel(None);
        let (worker_event_tx, worker_event_rx) = mpsc::channel(2);
        let (event_tx, event_rx) = mpsc::channel(LIFECYCLE_CHANNEL_CAPACITY);
        let (result_tx, result_rx) = oneshot::channel();
        let connecting = ConnectingSupervisor {
            identity,
            target_name,
            read_only,
            limits: self.limits.clone(),
            reservation,
            running: Some(running),
            command_tx,
            command_rx: Some(command_rx),
            output_tx,
            output_rx,
            close_rx,
            close_tx: close_tx.clone(),
            cancel_tx,
            cancel_rx,
            activity_tx,
            activity_rx,
            final_tx,
            final_rx,
            event_tx,
            event_rx,
            audit_tx: self.audit_tx.clone(),
            audit: self.audit.clone(),
            remote_address,
            worker_event_rx,
            worker_event_tx,
            result_tx,
            #[cfg(test)]
            panic_for_test: self.panic_supervisor_for_test,
            #[cfg(test)]
            connecting_panic_for_test: self.connecting_panic_for_test,
        };
        let (start_tx, start_rx) = oneshot::channel();
        let supervisors = Arc::clone(&self.supervisors);
        {
            let mut registry = supervisors
                .inner
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            debug_assert!(!registry.shutting_down);
            let id = registry.next_id;
            registry.next_id = registry.next_id.wrapping_add(1);
            let registry_for_task = Arc::clone(&supervisors);
            let task = tokio::spawn(async move {
                let _completion = SupervisorCompletion {
                    registry: registry_for_task,
                    id,
                };
                let _ = start_rx.await;
                supervise_connecting(connecting).await;
            });
            registry.active.insert(
                id,
                ActiveSupervisor {
                    close_tx: close_tx.clone(),
                    _task: task,
                },
            );
        }
        let _ = start_tx.send(());
        drop(admission);
        result_rx
            .await
            .unwrap_or(Err(SessionError::BackendUnavailable))
    }

    fn record_denial(
        &self,
        identity: &Identity,
        target_name: &str,
        remote_address: Option<SocketAddr>,
        category: DenialCategory,
        reason: DenialReason,
    ) -> Result<(), ()> {
        let Some(audit) = &self.audit else {
            return Ok(());
        };
        let correlation_id = CorrelationId::generate().map_err(|_| ())?;
        let occurred_at = AuditTimestamp::now().map_err(|_| ())?;
        let target = ResolvedAuditTarget::from_resolved_name(target_name);
        audit
            .record(&AuditEvent::access_denied(
                correlation_id,
                category,
                reason,
                Some(identity),
                Some(&target),
                remote_address,
                occurred_at,
            ))
            .map_err(|_| ())
    }

    fn record_backend_resolution_denial(
        &self,
        identity: &Identity,
        target_name: &str,
        remote_address: Option<SocketAddr>,
        error: SessionError,
    ) -> Result<(), ()> {
        let reason = match error {
            SessionError::SshPolicyDenied => DenialReason::SshUserPolicyDenied,
            SessionError::SpawnUnavailable => DenialReason::SessionUnavailable,
            _ => return Ok(()),
        };
        self.record_denial(
            identity,
            target_name,
            remote_address,
            DenialCategory::Target,
            reason,
        )
    }

    pub async fn shutdown(&self) {
        let _shutdown = self.supervisors.shutdown.lock().await;
        let admission = self.supervisors.admission.write().await;
        let close_senders = {
            let mut registry = self
                .supervisors
                .inner
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            registry.shutting_down = true;
            self.capacity.close_pending();
            registry
                .active
                .values()
                .map(|active| active.close_tx.clone())
                .collect::<Vec<_>>()
        };
        drop(admission);
        for close_tx in close_senders {
            request_close(&close_tx, SessionCloseReason::ManagerShutdown);
        }
        loop {
            let completed = self.supervisors.completed.notified();
            if self
                .supervisors
                .inner
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .active
                .is_empty()
            {
                break;
            }
            completed.await;
        }
    }
}

fn validate_resize(size: &Resize) -> Result<(), SessionError> {
    Resize::new(size.cols, size.rows)
        .map(|_| ())
        .map_err(|_| SessionError::InvalidResize)
}

fn lifecycle_event(
    identity: &Identity,
    target_name: &str,
    transition: LifecycleTransition,
) -> LifecycleEvent {
    LifecycleEvent {
        identity: identity.clone(),
        target: target_name.to_owned(),
        at: SystemTime::now(),
        transition,
    }
}

pub struct Session {
    command_tx: mpsc::Sender<SessionCommand>,
    output_rx: mpsc::Receiver<Vec<u8>>,
    close_tx: watch::Sender<Option<SessionCloseReason>>,
    final_rx: watch::Receiver<Option<SessionClosed>>,
    event_rx: mpsc::Receiver<LifecycleEvent>,
    read_only: bool,
}

impl std::fmt::Debug for Session {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Session")
            .field("state", &self.state())
            .field("read_only", &self.read_only)
            .finish_non_exhaustive()
    }
}

impl Session {
    pub fn state(&self) -> SessionState {
        if self.final_rx.borrow().is_some() {
            SessionState::Closed
        } else {
            SessionState::Running
        }
    }

    pub async fn read(&mut self) -> Result<Vec<u8>, SessionError> {
        self.output_rx.recv().await.ok_or(SessionError::Closed)
    }

    pub async fn write(&self, bytes: Vec<u8>) -> Result<(), SessionError> {
        if bytes.len() > MAX_BINARY_BYTES {
            return Err(SessionError::InputTooLarge);
        }
        if self.read_only {
            return Err(SessionError::ReadOnly);
        }
        self.command_tx
            .send(SessionCommand::Input(bytes))
            .await
            .map_err(|_| SessionError::Closed)
    }

    pub async fn resize(&self, size: Resize) -> Result<(), SessionError> {
        validate_resize(&size)?;
        self.command_tx
            .send(SessionCommand::Resize(size))
            .await
            .map_err(|_| SessionError::Closed)
    }

    pub async fn close(&mut self) -> Result<SessionClosed, SessionError> {
        request_close(&self.close_tx, SessionCloseReason::Explicit);
        self.wait_closed().await
    }

    pub(crate) async fn transport_dropped(&mut self) -> Result<SessionClosed, SessionError> {
        request_close(&self.close_tx, SessionCloseReason::TransportDropped);
        self.wait_closed().await
    }

    pub(crate) async fn close_from_bridge(
        &mut self,
        reason: SessionCloseReason,
    ) -> Result<SessionClosed, SessionError> {
        debug_assert!(matches!(
            reason,
            SessionCloseReason::ProtocolViolation
                | SessionCloseReason::PolicyViolation
                | SessionCloseReason::InternalFailure
        ));
        request_close(&self.close_tx, reason);
        self.wait_closed().await
    }

    pub async fn wait_closed(&mut self) -> Result<SessionClosed, SessionError> {
        loop {
            if let Some(closed) = *self.final_rx.borrow() {
                return Ok(closed);
            }
            self.final_rx
                .changed()
                .await
                .map_err(|_| SessionError::BackendUnavailable)?;
        }
    }

    pub async fn next_event(&mut self) -> Option<LifecycleEvent> {
        self.event_rx.recv().await
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        if self.final_rx.borrow().is_none() {
            request_close(&self.close_tx, SessionCloseReason::HandleDropped);
        }
    }
}

fn request_close(sender: &watch::Sender<Option<SessionCloseReason>>, reason: SessionCloseReason) {
    sender.send_if_modified(|current| {
        if current.is_some() {
            false
        } else {
            *current = Some(reason);
            true
        }
    });
}

enum SessionCommand {
    Input(Vec<u8>),
    Resize(Resize),
}

#[derive(Debug, Clone, Copy)]
enum WorkerEvent {
    ReaderEnded,
    WriterEnded,
}

async fn read_output(
    mut reader: crate::pty_backend::PtyReader,
    output: mpsc::Sender<Vec<u8>>,
    mut cancel: watch::Receiver<bool>,
    activity: watch::Sender<Instant>,
    worker_events: mpsc::Sender<WorkerEvent>,
) {
    let mut buffer = vec![0_u8; MAX_BINARY_BYTES];
    loop {
        let count = tokio::select! {
            biased;
            _ = cancelled(&mut cancel) => break,
            result = reader.read(&mut buffer) => match result {
                Ok(0) | Err(_) => break,
                Ok(count) => count,
            },
        };
        let chunk = buffer[..count].to_vec();
        let sent = tokio::select! {
            biased;
            _ = cancelled(&mut cancel) => false,
            result = output.send(chunk) => result.is_ok(),
        };
        if !sent {
            break;
        }
        activity.send_replace(Instant::now());
    }
    let _ = worker_events.try_send(WorkerEvent::ReaderEnded);
}

async fn write_input(
    mut writer: crate::pty_backend::PtyWriter,
    mut commands: mpsc::Receiver<SessionCommand>,
    mut cancel: watch::Receiver<bool>,
    activity: watch::Sender<Instant>,
    worker_events: mpsc::Sender<WorkerEvent>,
    read_only: bool,
) {
    loop {
        let command = tokio::select! {
            biased;
            _ = cancelled(&mut cancel) => break,
            command = commands.recv() => match command {
                Some(command) => command,
                None => break,
            },
        };
        let result = match command {
            SessionCommand::Input(bytes) if read_only => {
                let _ = bytes;
                continue;
            }
            SessionCommand::Input(bytes) => {
                if bytes.is_empty() {
                    continue;
                }
                tokio::select! {
                    biased;
                    _ = cancelled(&mut cancel) => break,
                    result = async {
                        writer.write_all(&bytes).await?;
                        writer.flush().await
                    } => result.map(|()| true),
                }
            }
            SessionCommand::Resize(size) => writer
                .resize(size)
                .map(|()| true)
                .map_err(|_| std::io::Error::other("curated backend failure")),
        };
        match result {
            Ok(true) => {
                activity.send_replace(Instant::now());
            }
            Ok(false) => {}
            Err(_) => break,
        }
    }
    let _ = worker_events.try_send(WorkerEvent::WriterEnded);
}

async fn cancelled(receiver: &mut watch::Receiver<bool>) {
    while !*receiver.borrow_and_update() {
        if receiver.changed().await.is_err() {
            break;
        }
    }
}

struct Supervisor {
    state: StateMachine,
    identity: Identity,
    target_name: String,
    limits: Limits,
    created_at: Instant,
    reservation: Reservation,
    child: crate::pty_backend::PtyChild,
    close_rx: watch::Receiver<Option<SessionCloseReason>>,
    cancel_tx: watch::Sender<bool>,
    activity_rx: watch::Receiver<Instant>,
    final_tx: watch::Sender<Option<SessionClosed>>,
    event_tx: mpsc::Sender<LifecycleEvent>,
    audit_tx: broadcast::Sender<LifecycleEvent>,
    worker_event_rx: mpsc::Receiver<WorkerEvent>,
    reader_task: Option<JoinHandle<()>>,
    writer_task: Option<JoinHandle<()>>,
    diagnostic_tasks: Vec<JoinHandle<()>>,
    persistent_audit: Option<PersistentAudit>,
    #[cfg(test)]
    panic_for_test: bool,
}

struct PersistentAudit {
    log: Arc<AuditLog>,
    session_id: SessionId,
    started_at: AuditTimestamp,
    remote_address: Option<SocketAddr>,
}

struct ConnectingSupervisor {
    identity: Identity,
    target_name: String,
    read_only: bool,
    limits: Limits,
    reservation: Reservation,
    running: Option<SpawnedBackend>,
    command_tx: mpsc::Sender<SessionCommand>,
    command_rx: Option<mpsc::Receiver<SessionCommand>>,
    output_tx: mpsc::Sender<Vec<u8>>,
    output_rx: mpsc::Receiver<Vec<u8>>,
    close_tx: watch::Sender<Option<SessionCloseReason>>,
    close_rx: watch::Receiver<Option<SessionCloseReason>>,
    cancel_tx: watch::Sender<bool>,
    cancel_rx: watch::Receiver<bool>,
    activity_tx: watch::Sender<Instant>,
    activity_rx: watch::Receiver<Instant>,
    final_tx: watch::Sender<Option<SessionClosed>>,
    final_rx: watch::Receiver<Option<SessionClosed>>,
    event_tx: mpsc::Sender<LifecycleEvent>,
    event_rx: mpsc::Receiver<LifecycleEvent>,
    audit_tx: broadcast::Sender<LifecycleEvent>,
    audit: Option<Arc<AuditLog>>,
    remote_address: Option<SocketAddr>,
    worker_event_tx: mpsc::Sender<WorkerEvent>,
    worker_event_rx: mpsc::Receiver<WorkerEvent>,
    result_tx: oneshot::Sender<Result<Session, SessionError>>,
    #[cfg(test)]
    panic_for_test: bool,
    #[cfg(test)]
    connecting_panic_for_test: Option<ConnectingPanicPoint>,
}

struct ConnectingParts {
    reader: Option<crate::pty_backend::PtyReader>,
    writer: Option<crate::pty_backend::PtyWriter>,
    child: crate::pty_backend::PtyChild,
    admission_rx: mpsc::UnboundedReceiver<SshDiagnosticClass>,
    diagnostic_tasks: Vec<JoinHandle<()>>,
}

struct ConnectingExecution {
    connecting: Option<ConnectingSupervisor>,
    parts: Option<ConnectingParts>,
    persistent_audit: Option<PersistentAudit>,
    handoff: Option<ConnectingHandoff>,
}

struct ConnectingHandoff {
    connecting: ConnectingSupervisor,
    parts: ConnectingParts,
    persistent_audit: Option<PersistentAudit>,
    lifecycle_started: bool,
    reader_task: Option<JoinHandle<()>>,
    writer_task: Option<JoinHandle<()>>,
}

fn split_connecting_backend(
    running: SpawnedBackend,
    cancel: watch::Receiver<bool>,
) -> ConnectingParts {
    match running {
        SpawnedBackend::Pty(running) => {
            let (reader, writer, child) = running.into_parts();
            let (admission_tx, admission_rx) = mpsc::unbounded_channel();
            let _ = admission_tx.send(SshDiagnosticClass::Authenticated);
            ConnectingParts {
                reader: Some(reader),
                writer: Some(writer),
                child,
                admission_rx,
                diagnostic_tasks: Vec::new(),
            }
        }
        SpawnedBackend::Ssh(running, classifier) => {
            let (reader, writer, child, mut raw_stderr, client_log) = running.into_parts();
            let (admission_tx, admission_rx) = mpsc::unbounded_channel();
            let mut raw_cancel = cancel.clone();
            let raw_task = tokio::spawn(async move {
                let mut buffer = [0_u8; 4096];
                loop {
                    tokio::select! {
                        biased;
                        _ = cancelled(&mut raw_cancel) => break,
                        result = raw_stderr.read(&mut buffer) => {
                            if !matches!(result, Ok(count) if count != 0) {
                                break;
                            }
                        }
                    }
                }
            });
            let mut log_cancel = cancel;
            let log_task = tokio::spawn(async move {
                drain_client_log(client_log, classifier, admission_tx, &mut log_cancel).await;
            });
            ConnectingParts {
                reader: Some(reader),
                writer: Some(writer),
                child,
                admission_rx,
                diagnostic_tasks: vec![raw_task, log_task],
            }
        }
        #[cfg(test)]
        SpawnedBackend::TestSsh(running, admission_rx) => {
            let (reader, writer, child) = running.into_parts();
            ConnectingParts {
                reader: Some(reader),
                writer: Some(writer),
                child,
                admission_rx,
                diagnostic_tasks: Vec::new(),
            }
        }
    }
}

async fn drain_client_log(
    client_log: SshClientLog,
    mut classifier: SshDiagnosticClassifier,
    admission: mpsc::UnboundedSender<SshDiagnosticClass>,
    cancel: &mut watch::Receiver<bool>,
) {
    let mut buffer = [0_u8; 4096];
    let mut reported = false;
    loop {
        let result = tokio::select! {
            biased;
            _ = cancelled(cancel) => return,
            result = client_log.read(&mut buffer) => result,
        };
        let count = match result {
            Ok(0) | Err(_) => {
                if !reported {
                    let _ = admission.send(classifier.finish());
                }
                return;
            }
            Ok(count) => count,
        };
        if !reported {
            classifier.push(&buffer[..count]);
            if let Some(class) = classifier.classification() {
                reported = true;
                let _ = admission.send(class);
            }
        }
    }
}

enum ConnectingOutcome {
    Authenticated,
    Rejected(SshDiagnosticClass),
    Closed(SessionCloseReason),
    CallerDropped,
    ChildExited,
}

async fn supervise_connecting(mut connecting: ConnectingSupervisor) {
    let running = connecting
        .running
        .take()
        .expect("connecting backend is split exactly once");
    let parts = split_connecting_backend(running, connecting.cancel_rx.clone());
    let mut execution = ConnectingExecution {
        connecting: Some(connecting),
        parts: Some(parts),
        persistent_audit: None,
        handoff: None,
    };
    if AssertUnwindSafe(run_connecting(&mut execution))
        .catch_unwind()
        .await
        .is_err()
    {
        recover_connecting_unwind(&mut execution).await;
    }
}

async fn run_connecting(execution: &mut ConnectingExecution) {
    let connecting = execution
        .connecting
        .as_mut()
        .expect("connecting context remains owned until handoff");
    let parts = execution
        .parts
        .as_mut()
        .expect("connecting process remains owned until handoff");
    #[cfg(test)]
    if connecting.connecting_panic_for_test == Some(ConnectingPanicPoint::BeforeAdmission) {
        panic!("injected connecting unwind before admission");
    }

    let deadline = tokio::time::sleep(SSH_ADMISSION_TIMEOUT);
    tokio::pin!(deadline);
    let outcome = tokio::select! {
        biased;
        changed = connecting.close_rx.changed() => {
            let reason = if changed.is_err() {
                SessionCloseReason::HandleDropped
            } else {
                (*connecting.close_rx.borrow_and_update())
                    .unwrap_or(SessionCloseReason::HandleDropped)
            };
            ConnectingOutcome::Closed(reason)
        },
        _ = connecting.result_tx.closed() => ConnectingOutcome::CallerDropped,
        diagnostic = parts.admission_rx.recv() => match diagnostic {
            Some(SshDiagnosticClass::Authenticated) => ConnectingOutcome::Authenticated,
            Some(class) => ConnectingOutcome::Rejected(class),
            None => ConnectingOutcome::Rejected(SshDiagnosticClass::GenericFailure),
        },
        observed = parts.child.wait_for_exit_observed() => match observed {
            Ok(()) => ConnectingOutcome::ChildExited,
            Err(_) => ConnectingOutcome::Rejected(SshDiagnosticClass::GenericFailure),
        },
        _ = &mut deadline => ConnectingOutcome::Rejected(SshDiagnosticClass::ConnectionFailed),
    };

    if !matches!(outcome, ConnectingOutcome::Authenticated) {
        connecting.cancel_tx.send_replace(true);
        let _ = terminate_until_proven(&mut parts.child).await;
        for task in parts.diagnostic_tasks.drain(..) {
            join_worker(task).await;
        }
        let connecting = execution
            .connecting
            .take()
            .expect("connecting result is completed exactly once");
        match outcome {
            ConnectingOutcome::Rejected(class) => {
                let (error, category, reason) = ssh_denial(class);
                let result = if record_access_denial(
                    connecting.audit.as_deref(),
                    &connecting.identity,
                    &connecting.target_name,
                    connecting.remote_address,
                    category,
                    reason,
                )
                .is_ok()
                {
                    Err(error)
                } else {
                    Err(SessionError::AuditUnavailable)
                };
                let _ = connecting.result_tx.send(result);
            }
            ConnectingOutcome::ChildExited => {
                let (error, category, reason) = ssh_denial(SshDiagnosticClass::GenericFailure);
                let result = if record_access_denial(
                    connecting.audit.as_deref(),
                    &connecting.identity,
                    &connecting.target_name,
                    connecting.remote_address,
                    category,
                    reason,
                )
                .is_ok()
                {
                    Err(error)
                } else {
                    Err(SessionError::AuditUnavailable)
                };
                let _ = connecting.result_tx.send(result);
            }
            ConnectingOutcome::Closed(SessionCloseReason::ManagerShutdown) => {
                let _ = connecting.result_tx.send(Err(SessionError::ManagerClosed));
            }
            ConnectingOutcome::Closed(_) => {
                let _ = connecting
                    .result_tx
                    .send(Err(SessionError::BackendUnavailable));
            }
            ConnectingOutcome::CallerDropped => {
                let _ = record_access_denial(
                    connecting.audit.as_deref(),
                    &connecting.identity,
                    &connecting.target_name,
                    connecting.remote_address,
                    DenialCategory::Target,
                    DenialReason::SessionCancelled,
                );
            }
            ConnectingOutcome::Authenticated => unreachable!(),
        }
        return;
    }

    let persistent_audit = match connecting
        .audit
        .as_ref()
        .map(|audit| {
            Ok::<_, SessionError>(PersistentAudit {
                log: Arc::clone(audit),
                session_id: SessionId::generate().map_err(|_| SessionError::AuditUnavailable)?,
                started_at: AuditTimestamp::now().map_err(|_| SessionError::AuditUnavailable)?,
                remote_address: connecting.remote_address,
            })
        })
        .transpose()
    {
        Ok(persistent) => persistent,
        Err(error) => {
            cleanup_connecting(parts, &connecting.cancel_tx).await;
            let connecting = execution
                .connecting
                .take()
                .expect("connecting result is completed exactly once");
            let _ = connecting.result_tx.send(Err(error));
            return;
        }
    };
    if let Some(audit) = &persistent_audit {
        let target = ResolvedAuditTarget::from_resolved_name(&connecting.target_name);
        if audit
            .log
            .record(&AuditEvent::session_started(
                audit.session_id.clone(),
                &connecting.identity,
                &target,
                connecting.remote_address,
                audit.started_at.clone(),
            ))
            .is_err()
        {
            cleanup_connecting(parts, &connecting.cancel_tx).await;
            let connecting = execution
                .connecting
                .take()
                .expect("connecting result is completed exactly once");
            let _ = connecting
                .result_tx
                .send(Err(SessionError::AuditUnavailable));
            return;
        }
    }
    execution.persistent_audit = persistent_audit;
    #[cfg(test)]
    if connecting.connecting_panic_for_test == Some(ConnectingPanicPoint::AfterAuditStart) {
        panic!("injected connecting unwind after persisted audit start");
    }

    execution.handoff = Some(ConnectingHandoff {
        connecting: execution
            .connecting
            .take()
            .expect("authenticated connection hands off exactly once"),
        parts: execution
            .parts
            .take()
            .expect("authenticated process hands off exactly once"),
        persistent_audit: execution.persistent_audit.take(),
        lifecycle_started: false,
        reader_task: None,
        writer_task: None,
    });
    #[cfg(test)]
    if execution.handoff.as_ref().is_some_and(|handoff| {
        handoff.connecting.connecting_panic_for_test == Some(ConnectingPanicPoint::AfterHandoffTake)
    }) {
        panic!("injected connecting unwind after handoff take");
    }
    let created_at = Instant::now();
    let mut state = StateMachine::new();
    state.start().expect("authenticated admission starts once");
    {
        let handoff = execution
            .handoff
            .as_mut()
            .expect("authenticated handoff remains owned during construction");
        for transition in [LifecycleTransition::Created, LifecycleTransition::Running] {
            let event = lifecycle_event(
                &handoff.connecting.identity,
                &handoff.connecting.target_name,
                transition,
            );
            handoff
                .connecting
                .event_tx
                .try_send(event.clone())
                .expect("lifecycle channel holds every possible transition");
            let _ = handoff.connecting.audit_tx.send(event);
        }
        handoff.lifecycle_started = true;
        let reader = handoff
            .parts
            .reader
            .take()
            .expect("handoff reader starts exactly once");
        handoff.reader_task = Some(tokio::spawn(read_output(
            reader,
            handoff.connecting.output_tx.clone(),
            handoff.connecting.cancel_rx.clone(),
            handoff.connecting.activity_tx.clone(),
            handoff.connecting.worker_event_tx.clone(),
        )));
        let writer = handoff
            .parts
            .writer
            .take()
            .expect("handoff writer starts exactly once");
        let command_rx = handoff
            .connecting
            .command_rx
            .take()
            .expect("handoff command receiver starts exactly once");
        handoff.writer_task = Some(tokio::spawn(write_input(
            writer,
            command_rx,
            handoff.connecting.cancel_rx.clone(),
            handoff.connecting.activity_tx.clone(),
            handoff.connecting.worker_event_tx.clone(),
            handoff.connecting.read_only,
        )));
    }
    let ConnectingHandoff {
        connecting,
        parts,
        persistent_audit,
        lifecycle_started: _,
        reader_task,
        writer_task,
    } = execution
        .handoff
        .take()
        .expect("authenticated handoff completes exactly once");
    let ConnectingSupervisor {
        identity,
        target_name,
        read_only,
        limits,
        reservation,
        running: _,
        command_tx,
        command_rx: _,
        output_tx: _,
        output_rx,
        close_tx,
        close_rx,
        cancel_tx,
        cancel_rx: _,
        activity_tx: _,
        activity_rx,
        final_tx,
        final_rx,
        event_tx,
        event_rx,
        audit_tx,
        audit: _,
        remote_address: _,
        worker_event_tx: _,
        worker_event_rx,
        result_tx,
        #[cfg(test)]
        panic_for_test,
        #[cfg(test)]
            connecting_panic_for_test: _,
    } = connecting;
    let supervisor = Supervisor {
        state,
        identity,
        target_name,
        limits,
        created_at,
        reservation,
        child: parts.child,
        close_rx,
        cancel_tx,
        activity_rx,
        final_tx,
        event_tx,
        audit_tx,
        worker_event_rx,
        reader_task,
        writer_task,
        diagnostic_tasks: parts.diagnostic_tasks,
        persistent_audit,
        #[cfg(test)]
        panic_for_test,
    };
    let session = Session {
        command_tx,
        output_rx,
        close_tx,
        final_rx,
        event_rx,
        read_only,
    };
    let _ = result_tx.send(Ok(session));
    supervise(supervisor).await;
}

async fn cleanup_connecting(parts: &mut ConnectingParts, cancel: &watch::Sender<bool>) {
    cancel.send_replace(true);
    let _ = terminate_until_proven(&mut parts.child).await;
    for task in parts.diagnostic_tasks.drain(..) {
        join_worker(task).await;
    }
}

async fn recover_connecting_unwind(execution: &mut ConnectingExecution) {
    if let Some(mut handoff) = execution.handoff.take() {
        handoff.connecting.cancel_tx.send_replace(true);
        let (status, _) = terminate_until_proven(&mut handoff.parts.child).await;
        if let Some(task) = handoff.reader_task.take() {
            join_worker(task).await;
        }
        if let Some(task) = handoff.writer_task.take() {
            join_worker(task).await;
        }
        for task in handoff.parts.diagnostic_tasks.drain(..) {
            join_worker(task).await;
        }
        let outcome = Some(ChildOutcome::from_status(status));
        if handoff.lifecycle_started {
            let event = lifecycle_event(
                &handoff.connecting.identity,
                &handoff.connecting.target_name,
                LifecycleTransition::Closed {
                    reason: SessionCloseReason::SupervisorUnwind,
                    outcome,
                },
            );
            let _ = handoff.connecting.event_tx.try_send(event.clone());
            let _ = handoff.connecting.audit_tx.send(event);
        }
        if let Some(audit) = &handoff.persistent_audit
            && let Ok(ended_at) = AuditTimestamp::now()
        {
            let target = ResolvedAuditTarget::from_resolved_name(&handoff.connecting.target_name);
            let _ = audit.log.record(&AuditEvent::session_ended(
                audit.session_id.clone(),
                &handoff.connecting.identity,
                &target,
                audit.remote_address,
                audit.started_at.clone(),
                ended_at,
                AuditCloseReason::SupervisorUnwind,
                outcome.map(audit_outcome),
            ));
        }
        let _ = handoff
            .connecting
            .result_tx
            .send(Err(SessionError::BackendUnavailable));
        return;
    }
    let outcome = if let (Some(connecting), Some(parts)) =
        (execution.connecting.as_ref(), execution.parts.as_mut())
    {
        connecting.cancel_tx.send_replace(true);
        let (status, _) = terminate_until_proven(&mut parts.child).await;
        for task in parts.diagnostic_tasks.drain(..) {
            join_worker(task).await;
        }
        Some(ChildOutcome::from_status(status))
    } else {
        None
    };

    if let (Some(audit), Some(connecting)) = (
        execution.persistent_audit.as_ref(),
        execution.connecting.as_ref(),
    ) && let Ok(ended_at) = AuditTimestamp::now()
    {
        let target = ResolvedAuditTarget::from_resolved_name(&connecting.target_name);
        let _ = audit.log.record(&AuditEvent::session_ended(
            audit.session_id.clone(),
            &connecting.identity,
            &target,
            audit.remote_address,
            audit.started_at.clone(),
            ended_at,
            AuditCloseReason::SupervisorUnwind,
            outcome.map(audit_outcome),
        ));
    }

    if let Some(connecting) = execution.connecting.take() {
        let _ = connecting
            .result_tx
            .send(Err(SessionError::BackendUnavailable));
        // Dropping the connecting context releases its reservation only after
        // process-group cleanup has been positively confirmed above.
    }
}

async fn terminate_until_proven(
    child: &mut crate::pty_backend::PtyChild,
) -> (std::process::ExitStatus, bool) {
    let mut retried = false;
    loop {
        match child.terminate(CLEANUP_GRACE).await {
            Ok(status) => return (status, retried),
            Err(_) => {
                retried = true;
                tokio::time::sleep(CLEANUP_RETRY_DELAY).await;
            }
        }
    }
}

fn ssh_denial(class: SshDiagnosticClass) -> (SessionError, DenialCategory, DenialReason) {
    match class {
        SshDiagnosticClass::UnknownHostKey => (
            SessionError::SshHostKeyFailed,
            DenialCategory::HostKey,
            DenialReason::UnknownHostKey,
        ),
        SshDiagnosticClass::HostKeyMismatch => (
            SessionError::SshHostKeyFailed,
            DenialCategory::HostKey,
            DenialReason::HostKeyMismatch,
        ),
        SshDiagnosticClass::ConnectionFailed => (
            SessionError::SshConnectionFailed,
            DenialCategory::Target,
            DenialReason::SshConnectionFailed,
        ),
        SshDiagnosticClass::AuthenticationFailed => (
            SessionError::SshAuthenticationFailed,
            DenialCategory::Authentication,
            DenialReason::SshAuthenticationFailed,
        ),
        SshDiagnosticClass::GenericFailure | SshDiagnosticClass::Authenticated => (
            SessionError::SshFailed,
            DenialCategory::Target,
            DenialReason::SshFailed,
        ),
    }
}

fn record_access_denial(
    audit: Option<&AuditLog>,
    identity: &Identity,
    target_name: &str,
    remote_address: Option<SocketAddr>,
    category: DenialCategory,
    reason: DenialReason,
) -> Result<(), ()> {
    let Some(audit) = audit else {
        return Ok(());
    };
    let correlation_id = CorrelationId::generate().map_err(|_| ())?;
    let occurred_at = AuditTimestamp::now().map_err(|_| ())?;
    let target = ResolvedAuditTarget::from_resolved_name(target_name);
    audit
        .record(&AuditEvent::access_denied(
            correlation_id,
            category,
            reason,
            Some(identity),
            Some(&target),
            remote_address,
            occurred_at,
        ))
        .map_err(|_| ())
}

async fn supervise(mut supervisor: Supervisor) {
    let result = AssertUnwindSafe(run_supervisor(&mut supervisor))
        .catch_unwind()
        .await;
    let (reason, outcome) = match result {
        Ok(completion) => completion,
        Err(_) => {
            supervisor.cancel_tx.send_replace(true);
            let (status, _) = terminate_until_proven(&mut supervisor.child).await;
            let outcome = Some(ChildOutcome::from_status(status));
            join_supervisor_workers(&mut supervisor).await;
            (SessionCloseReason::SupervisorUnwind, outcome)
        }
    };
    complete_supervisor(supervisor, reason, outcome);
}

async fn run_supervisor(supervisor: &mut Supervisor) -> (SessionCloseReason, Option<ChildOutcome>) {
    #[cfg(test)]
    if supervisor.panic_for_test {
        panic!("injected supervisor unwind");
    }

    let absolute_deadline = supervisor.created_at + supervisor.limits.absolute_timeout;
    let idle_deadline = supervisor.created_at + supervisor.limits.idle_timeout;
    let absolute_sleep = sleep_until(absolute_deadline);
    let idle_sleep = sleep_until(idle_deadline);
    tokio::pin!(absolute_sleep);
    tokio::pin!(idle_sleep);

    let mut reason = loop {
        tokio::select! {
            biased;
            _ = &mut absolute_sleep => {
                break SessionCloseReason::Timeout(TimeoutKind::Absolute);
            }
            observed = supervisor.child.wait_for_exit_observed() => {
                break match observed {
                    Ok(()) => SessionCloseReason::ChildExited,
                    Err(_) => SessionCloseReason::BackendFailure,
                };
            }
            changed = supervisor.close_rx.changed() => {
                let requested = if changed.is_err() {
                    SessionCloseReason::HandleDropped
                } else {
                    (*supervisor.close_rx.borrow_and_update())
                        .unwrap_or(SessionCloseReason::HandleDropped)
                };
                break requested;
            }
            changed = supervisor.activity_rx.changed() => {
                if changed.is_ok() {
                    let last_activity = *supervisor.activity_rx.borrow_and_update();
                    idle_sleep.as_mut().reset(last_activity + supervisor.limits.idle_timeout);
                }
            }
            _ = &mut idle_sleep => {
                break SessionCloseReason::Timeout(TimeoutKind::Idle);
            }
            worker = supervisor.worker_event_rx.recv() => {
                let _ = worker;
                break match tokio::time::timeout(
                    CHILD_EXIT_SETTLE,
                    supervisor.child.wait_for_exit_observed(),
                ).await {
                    Ok(Ok(())) => SessionCloseReason::ChildExited,
                    Ok(Err(_)) | Err(_) => SessionCloseReason::BackendFailure,
                };
            }
        }
    };

    supervisor.cancel_tx.send_replace(true);
    let (status, retried) = terminate_until_proven(&mut supervisor.child).await;
    if retried {
        reason = SessionCloseReason::BackendFailure;
    }
    let outcome = Some(ChildOutcome::from_status(status));

    join_supervisor_workers(supervisor).await;
    (reason, outcome)
}

async fn join_supervisor_workers(supervisor: &mut Supervisor) {
    if let Some(reader) = supervisor.reader_task.take() {
        join_worker(reader).await;
    }
    if let Some(writer) = supervisor.writer_task.take() {
        join_worker(writer).await;
    }
    for task in supervisor.diagnostic_tasks.drain(..) {
        join_worker(task).await;
    }
}

fn complete_supervisor(
    mut supervisor: Supervisor,
    reason: SessionCloseReason,
    outcome: Option<ChildOutcome>,
) {
    let closed = supervisor
        .state
        .close(reason, outcome)
        .expect("supervisor closes a running session exactly once");
    if let Some(audit) = &supervisor.persistent_audit
        && let Ok(ended_at) = AuditTimestamp::now()
    {
        let target = ResolvedAuditTarget::from_resolved_name(&supervisor.target_name);
        let _ = audit.log.record(&AuditEvent::session_ended(
            audit.session_id.clone(),
            &supervisor.identity,
            &target,
            audit.remote_address,
            audit.started_at.clone(),
            ended_at,
            audit_close_reason(reason),
            outcome.map(audit_outcome),
        ));
    }
    supervisor.final_tx.send_replace(Some(closed));
    let closed_event = LifecycleEvent {
        identity: supervisor.identity,
        target: supervisor.target_name,
        at: SystemTime::now(),
        transition: LifecycleTransition::Closed { reason, outcome },
    };
    let _ = supervisor.event_tx.try_send(closed_event.clone());
    let _ = supervisor.audit_tx.send(closed_event);
    drop(supervisor.reservation);
}

fn audit_close_reason(reason: SessionCloseReason) -> AuditCloseReason {
    match reason {
        SessionCloseReason::ChildExited => AuditCloseReason::ChildExited,
        SessionCloseReason::Explicit => AuditCloseReason::Explicit,
        SessionCloseReason::TransportDropped => AuditCloseReason::WebsocketDisconnect,
        SessionCloseReason::ProtocolViolation => AuditCloseReason::ProtocolViolation,
        SessionCloseReason::PolicyViolation => AuditCloseReason::PolicyViolation,
        SessionCloseReason::InternalFailure => AuditCloseReason::InternalFailure,
        SessionCloseReason::HandleDropped => AuditCloseReason::Cancellation,
        SessionCloseReason::SupervisorUnwind => AuditCloseReason::SupervisorUnwind,
        SessionCloseReason::ManagerShutdown => AuditCloseReason::ManagerShutdown,
        SessionCloseReason::Timeout(TimeoutKind::Idle) => AuditCloseReason::IdleTimeout,
        SessionCloseReason::Timeout(TimeoutKind::Absolute) => AuditCloseReason::AbsoluteTimeout,
        SessionCloseReason::BackendFailure => AuditCloseReason::BackendFailure,
    }
}

fn audit_outcome(outcome: ChildOutcome) -> AuditOutcome {
    match outcome {
        ChildOutcome::Code(code) => AuditOutcome::Code(code),
        ChildOutcome::Signal(signal) => AuditOutcome::Signal(signal),
        ChildOutcome::Unavailable => AuditOutcome::Unavailable,
    }
}

async fn join_worker(mut worker: JoinHandle<()>) {
    if tokio::time::timeout(WORKER_JOIN_TIMEOUT, &mut worker)
        .await
        .is_err()
    {
        worker.abort();
        let _ = worker.await;
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        future::Future,
        os::unix::process::ExitStatusExt,
        sync::{
            Arc, Barrier, Mutex as StdMutex,
            atomic::{AtomicBool, AtomicUsize, Ordering},
        },
        thread,
        time::{Duration, SystemTime},
    };

    use crate::{
        audit::AuditLog,
        config::{Limits, PtyTarget, SshTarget, SshUserPolicy, Target, TargetAllowlist},
        protocol::{MAX_BINARY_BYTES, Resize},
        ticket::{Identity, TicketGrant, TicketStore},
    };
    use tokio::sync::{mpsc, watch};
    use tokio::time::Instant;

    use super::{
        Capacity, ChildOutcome, ConnectingPanicPoint, LifecycleEvent, LifecycleTransition,
        SessionCloseReason, SessionError, SessionManager, SessionState, StateMachine, TimeoutKind,
    };

    #[test]
    fn state_transitions_follow_created_running_closed_order() {
        let mut state = StateMachine::new();
        assert_eq!(state.state(), SessionState::Created);
        assert_eq!(state.start(), Ok(SessionState::Running));
        let terminal = state
            .close(SessionCloseReason::Explicit, None)
            .expect("running session closes");
        assert_eq!(terminal.state, SessionState::Closed);
        assert_eq!(terminal.reason, SessionCloseReason::Explicit);
        assert_eq!(terminal.outcome, None);
        assert_eq!(state.state(), SessionState::Closed);
    }

    #[test]
    fn state_invalid_and_repeated_transitions_are_deterministic() {
        let mut state = StateMachine::new();
        assert_eq!(state.start(), Ok(SessionState::Running));
        assert_eq!(state.start(), Err(SessionError::InvalidTransition));
        let first = state
            .close(SessionCloseReason::ChildExited, Some(ChildOutcome::Code(0)))
            .unwrap();
        let repeated = state
            .close(SessionCloseReason::BackendFailure, None)
            .unwrap();
        assert_eq!(repeated, first);
        assert_eq!(state.start(), Err(SessionError::InvalidTransition));
    }

    #[test]
    fn typed_child_outcomes_are_portable() {
        let cases = [
            (
                std::process::ExitStatus::from_raw(7 << 8),
                ChildOutcome::Code(7),
            ),
            (
                std::process::ExitStatus::from_raw(nix::libc::SIGTERM),
                ChildOutcome::Signal(nix::libc::SIGTERM as u8),
            ),
        ];
        for (status, expected) in cases {
            assert_eq!(ChildOutcome::from_status(status), expected);
        }
        assert_eq!(
            ChildOutcome::Unavailable.as_protocol(),
            crate::protocol::ExitStatus::Unavailable
        );
    }

    #[test]
    fn typed_close_reasons_distinguish_timeout_and_control_paths() {
        let reasons = [
            SessionCloseReason::Explicit,
            SessionCloseReason::TransportDropped,
            SessionCloseReason::ProtocolViolation,
            SessionCloseReason::PolicyViolation,
            SessionCloseReason::InternalFailure,
            SessionCloseReason::HandleDropped,
            SessionCloseReason::SupervisorUnwind,
            SessionCloseReason::ManagerShutdown,
            SessionCloseReason::Timeout(TimeoutKind::Idle),
            SessionCloseReason::Timeout(TimeoutKind::Absolute),
            SessionCloseReason::ChildExited,
            SessionCloseReason::BackendFailure,
        ];
        for (index, left) in reasons.iter().enumerate() {
            for (other_index, right) in reasons.iter().enumerate() {
                assert_eq!(left == right, index == other_index);
            }
        }
    }

    #[test]
    fn typed_errors_are_stable_and_do_not_reflect_sensitive_values() {
        let hostile = "alice /secret/path --evil terminal-sentinel";
        let errors = [
            SessionError::GlobalLimit,
            SessionError::IdentityLimit,
            SessionError::SpawnUnavailable,
            SessionError::TargetUnavailable,
            SessionError::ManagerClosed,
            SessionError::BackendUnavailable,
            SessionError::AuditUnavailable,
            SessionError::SshHostKeyFailed,
            SessionError::SshConnectionFailed,
            SessionError::SshAuthenticationFailed,
            SessionError::SshPolicyDenied,
            SessionError::SshFailed,
            SessionError::Closed,
            SessionError::ReadOnly,
            SessionError::InputTooLarge,
            SessionError::InvalidResize,
            SessionError::InvalidTransition,
        ];
        for error in errors {
            let message = error.to_string();
            assert!(!message.contains(hostile));
            assert!(!message.contains("alice"));
            assert!(!message.contains("/secret"));
            assert!(message.len() <= 96);
        }
    }

    #[test]
    fn lifecycle_events_contain_only_identity_target_time_and_transition() {
        let event = LifecycleEvent {
            identity: Identity::new("alice").unwrap(),
            target: "configured-shell".to_owned(),
            at: SystemTime::UNIX_EPOCH + Duration::from_secs(5),
            transition: LifecycleTransition::Closed {
                reason: SessionCloseReason::Timeout(TimeoutKind::Idle),
                outcome: Some(ChildOutcome::Signal(9)),
            },
        };
        let debug = format!("{event:?}");
        assert!(debug.contains("alice"));
        assert!(debug.contains("configured-shell"));
        assert!(!debug.contains("terminal-sentinel"));
        assert!(!debug.contains("cookie"));
        assert!(!debug.contains("ticket"));
        assert!(!debug.contains("argv"));
    }

    fn limits(global: usize, per_identity: usize) -> Limits {
        Limits {
            max_sessions: global,
            max_sessions_per_user: per_identity,
            idle_timeout: Duration::from_secs(60),
            absolute_timeout: Duration::from_secs(600),
            session_requests_per_window: 10,
            session_request_window: Duration::from_secs(60),
            authentication_failures_per_window: 20,
            authentication_failure_window: Duration::from_secs(60),
        }
    }

    #[test]
    fn limits_enforce_global_and_per_identity_atomically() {
        let capacity = Capacity::new(&limits(2, 1));
        let alice = Identity::new("alice").unwrap();
        let bob = Identity::new("bob").unwrap();
        let carol = Identity::new("carol").unwrap();

        let alice_reservation = capacity.reserve(&alice).unwrap();
        assert!(matches!(
            capacity.reserve(&alice),
            Err(SessionError::IdentityLimit)
        ));
        let bob_reservation = capacity.reserve(&bob).unwrap();
        assert!(matches!(
            capacity.reserve(&carol),
            Err(SessionError::GlobalLimit)
        ));

        drop(alice_reservation);
        let carol_reservation = capacity.reserve(&carol).unwrap();
        assert_eq!(capacity.active(), (2, 1));
        drop((bob_reservation, carol_reservation));
        assert_eq!(capacity.active(), (0, 0));
    }

    #[test]
    fn pending_lease_reserves_global_capacity_before_spawn() {
        let capacity = Capacity::new(&limits(1, 1));
        let alice = Identity::new("alice").unwrap();
        let bob = Identity::new("bob").unwrap();
        let pending = capacity
            .reserve_pending(&alice, Instant::now() + Duration::from_secs(10))
            .unwrap();

        assert!(matches!(
            capacity.reserve(&bob),
            Err(SessionError::GlobalLimit)
        ));
        drop(pending);
        assert!(capacity.reserve(&bob).is_ok());
    }

    #[derive(Debug)]
    struct ManualCapacityClock(StdMutex<Instant>);

    impl super::CapacityClock for ManualCapacityClock {
        fn now(&self) -> Instant {
            *self.0.lock().unwrap()
        }
    }

    #[derive(Debug)]
    struct AdvancingCapacityClock {
        start: Instant,
        calls: std::sync::atomic::AtomicUsize,
    }

    impl super::CapacityClock for AdvancingCapacityClock {
        fn now(&self) -> Instant {
            if self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0 {
                self.start
            } else {
                self.start + Duration::from_secs(10)
            }
        }
    }

    #[test]
    fn pending_lease_expiry_uses_a_deterministic_exact_boundary_clock() {
        let start = Instant::now();
        let clock = Arc::new(ManualCapacityClock(StdMutex::new(start)));
        let capacity = Capacity::with_clock(&limits(1, 1), clock.clone());
        let alice = Identity::new("alice").unwrap();
        let bob = Identity::new("bob").unwrap();
        let pending = capacity
            .reserve_pending(&alice, start + Duration::from_secs(10))
            .unwrap();
        assert!(matches!(
            capacity.reserve(&bob),
            Err(SessionError::GlobalLimit)
        ));

        *clock.0.lock().unwrap() = start + Duration::from_secs(10);
        let replacement = capacity
            .reserve(&bob)
            .expect("capacity must recover at the exact deadline");
        drop((pending, replacement));
        assert_eq!(capacity.active(), (0, 0));
    }

    #[test]
    fn pending_deadline_is_rechecked_atomically_at_insertion() {
        let start = Instant::now();
        let capacity = Capacity::with_clock(
            &limits(1, 1),
            Arc::new(AdvancingCapacityClock {
                start,
                calls: std::sync::atomic::AtomicUsize::new(0),
            }),
        );
        let alice = Identity::new("alice").unwrap();

        assert!(matches!(
            capacity.reserve_pending(&alice, start + Duration::from_secs(10)),
            Err(SessionError::ReservationUnavailable)
        ));
        assert_eq!(capacity.active(), (0, 0));
    }

    #[test]
    fn pending_lease_reserves_per_identity_capacity_before_spawn() {
        let capacity = Capacity::new(&limits(2, 1));
        let alice = Identity::new("alice").unwrap();
        let pending = capacity
            .reserve_pending(&alice, Instant::now() + Duration::from_secs(10))
            .unwrap();

        assert!(matches!(
            capacity.reserve_pending(&alice, Instant::now() + Duration::from_secs(10)),
            Err(SessionError::IdentityLimit)
        ));
        assert_eq!(capacity.active(), (1, 1));
        drop(pending);
    }

    #[test]
    fn already_expired_pending_lease_is_rejected_without_consuming_capacity() {
        let capacity = Capacity::new(&limits(1, 1));
        let alice = Identity::new("alice").unwrap();
        let bob = Identity::new("bob").unwrap();
        assert!(matches!(
            capacity.reserve_pending(&alice, Instant::now()),
            Err(SessionError::ReservationUnavailable)
        ));

        let replacement = capacity
            .reserve_pending(&bob, Instant::now() + Duration::from_secs(10))
            .expect("a rejected expired lease must not retain capacity");
        assert_eq!(capacity.active(), (1, 1));
        drop(replacement);
        assert_eq!(capacity.active(), (0, 0));
    }

    #[test]
    fn concurrent_pending_leases_have_exactly_configured_winners() {
        let capacity = Arc::new(Capacity::new(&limits(4, 2)));
        let barrier = Arc::new(Barrier::new(17));
        let handles: Vec<_> = (0..16)
            .map(|index| {
                let capacity = Arc::clone(&capacity);
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    let identity = Identity::new(format!("user-{}", index % 2)).unwrap();
                    barrier.wait();
                    capacity.reserve_pending(&identity, Instant::now() + Duration::from_secs(10))
                })
            })
            .collect();
        barrier.wait();
        let reservations: Vec<_> = handles
            .into_iter()
            .filter_map(|handle| handle.join().unwrap().ok())
            .collect();
        assert_eq!(reservations.len(), 4);
        assert_eq!(capacity.active(), (4, 2));
        drop(reservations);
        assert_eq!(capacity.active(), (0, 0));
    }

    #[test]
    fn wrong_identity_cannot_activate_a_pending_lease() {
        let capacity = Capacity::new(&limits(1, 1));
        let alice = Identity::new("alice").unwrap();
        let bob = Identity::new("bob").unwrap();
        let pending = capacity
            .reserve_pending(&alice, Instant::now() + Duration::from_secs(10))
            .unwrap();

        assert!(matches!(
            pending.activate(&bob),
            Err(SessionError::ReservationUnavailable)
        ));
        assert_eq!(capacity.active(), (0, 0));
    }

    #[test]
    fn reservation_release_after_simulated_spawn_failure_is_exactly_once() {
        let capacity = Capacity::new(&limits(1, 1));
        let identity = Identity::new("alice").unwrap();
        let reservation = capacity.reserve(&identity).unwrap();
        assert_eq!(capacity.active(), (1, 1));
        drop(reservation);
        assert_eq!(capacity.active(), (0, 0));
        assert!(capacity.reserve(&identity).is_ok());
    }

    #[test]
    fn limits_concurrent_reservations_never_exceed_bounds() {
        let capacity = Arc::new(Capacity::new(&limits(4, 2)));
        let barrier = Arc::new(Barrier::new(17));
        let handles: Vec<_> = (0..16)
            .map(|_| {
                let capacity = Arc::clone(&capacity);
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    let identity = Identity::new("alice").unwrap();
                    barrier.wait();
                    capacity.reserve(&identity)
                })
            })
            .collect();
        barrier.wait();
        let reservations: Vec<_> = handles
            .into_iter()
            .filter_map(|handle| handle.join().unwrap().ok())
            .collect();
        assert_eq!(reservations.len(), 2);
        assert_eq!(capacity.active(), (2, 2));
        drop(reservations);
        assert_eq!(capacity.active(), (0, 0));
    }

    fn fixture_target(read_only: bool) -> PtyTarget {
        PtyTarget {
            name: "fixture".to_owned(),
            executable: std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/pty_child.sh"),
            argv: Vec::new(),
            read_only,
        }
    }

    fn allowlist(targets: &[PtyTarget]) -> TargetAllowlist {
        TargetAllowlist::new(targets.iter().cloned().map(Target::Pty).collect()).unwrap()
    }

    fn manager(limits: Limits, targets: &[PtyTarget]) -> SessionManager {
        SessionManager::new(limits, allowlist(targets))
    }

    #[derive(Clone, Copy)]
    enum SshAdmissionScript {
        Authenticated,
        AuthenticatedSingleProcess,
        Pending,
        Failure(crate::ssh::SshDiagnosticClass),
        AuthenticatedThenExit(u8),
        PendingThenExit(u8),
    }

    struct ScriptedSshBackend {
        script: SshAdmissionScript,
        spawn_count: AtomicUsize,
        spawned: watch::Sender<bool>,
        admission: StdMutex<Option<mpsc::UnboundedSender<crate::ssh::SshDiagnosticClass>>>,
        reaped: Arc<AtomicBool>,
        cleanup_failures: Arc<AtomicUsize>,
    }

    impl super::Backend for ScriptedSshBackend {
        fn spawn(
            &self,
            target: super::BackendSpawn,
            size: Resize,
        ) -> Result<super::SpawnedBackend, crate::pty_backend::BackendError> {
            assert!(matches!(target, super::BackendSpawn::Ssh { .. }));
            self.spawn_count.fetch_add(1, Ordering::SeqCst);
            let process_target = match self.script {
                SshAdmissionScript::AuthenticatedSingleProcess => PtyTarget {
                    name: "scripted-ssh-child".to_owned(),
                    executable: "/bin/sleep".into(),
                    argv: vec!["300".to_owned()],
                    read_only: false,
                },
                SshAdmissionScript::AuthenticatedThenExit(code)
                | SshAdmissionScript::PendingThenExit(code) => PtyTarget {
                    name: "scripted-ssh-child".to_owned(),
                    executable: "/bin/sh".into(),
                    argv: vec!["-c".to_owned(), format!("exit {code}")],
                    read_only: false,
                },
                _ => fixture_target(false),
            };
            let mut running = crate::pty_backend::PtyProcessBackend::spawn(&process_target, size)?;
            running.observe_reap(Arc::clone(&self.reaped));
            running.inject_cleanup_failures(Arc::clone(&self.cleanup_failures));
            let (admission_tx, admission_rx) = mpsc::unbounded_channel();
            match self.script {
                SshAdmissionScript::Authenticated
                | SshAdmissionScript::AuthenticatedSingleProcess
                | SshAdmissionScript::AuthenticatedThenExit(_) => {
                    let _ = admission_tx.send(crate::ssh::SshDiagnosticClass::Authenticated);
                }
                SshAdmissionScript::Failure(class) => {
                    let _ = admission_tx.send(class);
                }
                SshAdmissionScript::Pending | SshAdmissionScript::PendingThenExit(_) => {
                    *self.admission.lock().unwrap() = Some(admission_tx);
                }
            }
            self.spawned.send_replace(true);
            Ok(super::SpawnedBackend::TestSsh(running, admission_rx))
        }
    }

    struct SshAdmissionFixture {
        backend: Arc<ScriptedSshBackend>,
        audit: Arc<AuditLog>,
        audit_path: std::path::PathBuf,
        material_path: std::path::PathBuf,
        cleanup_failures: Arc<AtomicUsize>,
        _directory: tempfile::TempDir,
    }

    impl SshAdmissionFixture {
        fn new(script: SshAdmissionScript) -> Self {
            Self::build(script, false, false)
        }

        fn with_failing_audit(script: SshAdmissionScript) -> Self {
            Self::build(script, true, false)
        }

        fn with_blocked_cleanup(script: SshAdmissionScript) -> Self {
            Self::build(script, false, true)
        }

        fn build(script: SshAdmissionScript, failing_audit: bool, blocked_cleanup: bool) -> Self {
            let directory = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
            let audit_path = directory.path().join("audit.jsonl");
            let audit = Arc::new(AuditLog::open(&audit_path).unwrap());
            let material_path = directory.path().join("ssh-material");
            fs::copy(fixture_target(false).executable, &material_path).unwrap();
            if failing_audit {
                audit.fail_for_test();
            }
            let (spawned, _) = watch::channel(false);
            let cleanup_failures = Arc::new(AtomicUsize::new(if blocked_cleanup {
                usize::MAX
            } else {
                0
            }));
            Self {
                backend: Arc::new(ScriptedSshBackend {
                    script,
                    spawn_count: AtomicUsize::new(0),
                    spawned,
                    admission: StdMutex::new(None),
                    reaped: Arc::new(AtomicBool::new(false)),
                    cleanup_failures: Arc::clone(&cleanup_failures),
                }),
                audit,
                audit_path,
                material_path,
                cleanup_failures,
                _directory: directory,
            }
        }

        fn manager(&self) -> SessionManager {
            self.manager_with_policy(SshUserPolicy::Fixed("operator".to_owned()))
        }

        fn manager_with_connecting_panic(&self, point: ConnectingPanicPoint) -> SessionManager {
            self.manager().with_connecting_panic_for_test(point)
        }

        fn manager_with_policy(&self, user_policy: SshUserPolicy) -> SessionManager {
            let fixture = self.material_path.clone();
            let target = SshTarget {
                name: "remote".to_owned(),
                host: "host.example".to_owned(),
                port: 22,
                ssh_executable: fixture.clone(),
                identity_file: fixture.clone(),
                known_hosts: fixture,
                user_policy,
                read_only: false,
            };
            let prepared = crate::ssh::PreparedSshTargets::from_session_test_target(&target);
            let mut manager = SessionManager::new_with_audit(
                limits(1, 1),
                TargetAllowlist::new(vec![Target::Ssh(target)]).unwrap(),
                Arc::clone(&self.audit),
            )
            .with_prepared_ssh(Arc::new(prepared));
            manager.backend = self.backend.clone();
            manager
        }

        fn spawn_count(&self) -> usize {
            self.backend.spawn_count.load(Ordering::SeqCst)
        }

        async fn wait_spawned(&self) {
            let mut spawned = self.backend.spawned.subscribe();
            tokio::time::timeout(Duration::from_secs(3), spawned.wait_for(|spawned| *spawned))
                .await
                .expect("scripted SSH spawn timed out")
                .expect("scripted SSH spawn signal closed");
        }

        fn invalidate_material(&self) {
            fs::write(&self.material_path, b"changed after preparation").unwrap();
        }

        fn admit(&self) {
            self.backend
                .admission
                .lock()
                .unwrap()
                .as_ref()
                .expect("pending admission sender")
                .send(crate::ssh::SshDiagnosticClass::Authenticated)
                .unwrap();
        }

        fn was_reaped(&self) -> bool {
            self.backend.reaped.load(Ordering::SeqCst)
        }

        fn allow_cleanup(&self) {
            self.cleanup_failures.store(0, Ordering::SeqCst);
        }

        async fn wait_reaped(&self) {
            tokio::time::timeout(Duration::from_secs(3), async {
                while !self.was_reaped() {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("scripted SSH child was not reaped");
        }

        fn audit_events(&self) -> Vec<serde_json::Value> {
            fs::read_to_string(&self.audit_path)
                .unwrap_or_default()
                .lines()
                .map(|line| serde_json::from_str(line).unwrap())
                .collect()
        }
    }

    async fn assert_ssh_setup_denial(
        script: SshAdmissionScript,
        expected_error: SessionError,
        expected_category: &str,
        expected_reason: &str,
    ) {
        let fixture = SshAdmissionFixture::new(script);
        let manager = fixture.manager();
        let mut lifecycle = manager.subscribe_events();
        assert!(matches!(
            fixture_deadline(
                manager.start(
                    Identity::new("alice").unwrap(),
                    "remote",
                    Resize::new(80, 24).unwrap(),
                ),
                "SSH setup denial",
            )
            .await,
            Err(error) if error == expected_error
        ));
        fixture.wait_reaped().await;
        assert!(lifecycle.try_recv().is_err());
        let events = fixture.audit_events();
        let denials = events
            .iter()
            .filter(|event| event["event_type"] == "access-denied")
            .collect::<Vec<_>>();
        assert_eq!(denials.len(), 1);
        assert_eq!(denials[0]["category"], expected_category);
        assert_eq!(denials[0]["reason"], expected_reason);
        assert!(
            events
                .iter()
                .all(|event| event["event_type"] != "session-started"
                    && event["event_type"] != "session-ended")
        );
        assert_eq!(manager.capacity.active(), (0, 0));
    }

    async fn fixture_deadline<F: Future>(future: F, phase: &'static str) -> F::Output {
        tokio::time::timeout(Duration::from_secs(3), future)
            .await
            .unwrap_or_else(|_| panic!("{phase} timed out"))
    }

    #[tokio::test]
    async fn ssh_policy_denial_happens_before_spawn_and_releases_capacity() {
        let fixture = SshAdmissionFixture::new(SshAdmissionScript::Authenticated);
        let manager = fixture.manager_with_policy(crate::config::SshUserPolicy::Mapping(
            std::collections::BTreeMap::from([("bob".to_owned(), "operator".to_owned())]),
        ));

        assert!(matches!(
            manager
                .start(
                    Identity::new("alice").unwrap(),
                    "remote",
                    Resize::new(80, 24).unwrap(),
                )
                .await,
            Err(SessionError::SshPolicyDenied)
        ));
        assert_eq!(fixture.spawn_count(), 0);
        assert_eq!(manager.capacity.active(), (0, 0));
        let events = fixture.audit_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0]["event_type"], "access-denied");
        assert_eq!(events[0]["category"], "target");
        assert_eq!(events[0]["reason"], "ssh-user-policy-denied");
    }

    #[tokio::test]
    async fn ssh_pre_spawn_build_failure_has_one_denial_and_no_session_lifecycle() {
        for reserved in [false, true] {
            let fixture = SshAdmissionFixture::new(SshAdmissionScript::Authenticated);
            let manager = fixture.manager();
            let mut lifecycle = manager.subscribe_events();
            let identity = Identity::new("alice").unwrap();
            let reservation = if reserved {
                Some(
                    manager
                        .reserve(&identity, Instant::now() + Duration::from_secs(3))
                        .await
                        .unwrap(),
                )
            } else {
                None
            };
            fixture.invalidate_material();

            let result = match reservation {
                Some(reservation) => {
                    manager
                        .start_reserved(
                            reservation,
                            identity,
                            "remote",
                            Resize::new(80, 24).unwrap(),
                        )
                        .await
                }
                None => {
                    manager
                        .start(identity, "remote", Resize::new(80, 24).unwrap())
                        .await
                }
            };
            assert!(matches!(result, Err(SessionError::SpawnUnavailable)));
            assert_eq!(fixture.spawn_count(), 0);
            assert_eq!(manager.capacity.active(), (0, 0));
            assert!(lifecycle.try_recv().is_err());
            let events = fixture.audit_events();
            assert_eq!(events.len(), 1);
            assert_eq!(events[0]["event_type"], "access-denied");
            assert_eq!(events[0]["category"], "target");
            assert_eq!(events[0]["reason"], "session-unavailable");
        }
    }

    #[tokio::test]
    async fn connecting_unwind_before_handoff_terminates_reaps_and_releases_capacity() {
        let fixture = SshAdmissionFixture::new(SshAdmissionScript::Pending);
        let manager = fixture.manager_with_connecting_panic(ConnectingPanicPoint::BeforeAdmission);
        let mut lifecycle = manager.subscribe_events();

        assert!(matches!(
            fixture_deadline(
                manager.start(
                    Identity::new("alice").unwrap(),
                    "remote",
                    Resize::new(80, 24).unwrap(),
                ),
                "pre-admission unwind result",
            )
            .await,
            Err(SessionError::BackendUnavailable)
        ));
        fixture.wait_reaped().await;
        assert_eq!(manager.capacity.active(), (0, 0));
        assert_eq!(manager.supervisor_count_for_test(), 0);
        assert!(lifecycle.try_recv().is_err());
        assert!(fixture.audit_events().is_empty());
    }

    #[tokio::test]
    async fn connecting_unwind_after_persisted_start_emits_one_end_and_reaps() {
        let fixture = SshAdmissionFixture::new(SshAdmissionScript::Authenticated);
        let manager = fixture.manager_with_connecting_panic(ConnectingPanicPoint::AfterAuditStart);
        let mut lifecycle = manager.subscribe_events();

        assert!(matches!(
            fixture_deadline(
                manager.start(
                    Identity::new("alice").unwrap(),
                    "remote",
                    Resize::new(80, 24).unwrap(),
                ),
                "post-audit unwind result",
            )
            .await,
            Err(SessionError::BackendUnavailable)
        ));
        fixture.wait_reaped().await;
        assert_eq!(manager.capacity.active(), (0, 0));
        assert!(lifecycle.try_recv().is_err());
        let events = fixture.audit_events();
        assert_eq!(
            events
                .iter()
                .filter(|event| event["event_type"] == "session-started")
                .count(),
            1
        );
        let ended = events
            .iter()
            .filter(|event| event["event_type"] == "session-ended")
            .collect::<Vec<_>>();
        assert_eq!(ended.len(), 1);
        assert_eq!(ended[0]["close_reason"], "supervisor-unwind");
    }

    #[tokio::test]
    async fn connecting_unwind_after_handoff_take_retains_cleanup_and_audit_owner() {
        let fixture = SshAdmissionFixture::new(SshAdmissionScript::AuthenticatedSingleProcess);
        let manager = fixture.manager_with_connecting_panic(ConnectingPanicPoint::AfterHandoffTake);
        let mut lifecycle = manager.subscribe_events();

        let start = manager.start(
            Identity::new("alice").unwrap(),
            "remote",
            Resize::new(80, 24).unwrap(),
        );
        tokio::pin!(start);
        let mut delivered_during_cleanup = None;
        tokio::time::timeout(Duration::from_secs(10), async {
            while !fixture.was_reaped() {
                tokio::select! {
                    result = &mut start => {
                        delivered_during_cleanup = Some(result);
                        break;
                    }
                    () = tokio::task::yield_now() => {}
                }
            }
        })
        .await
        .expect("post-handoff-take process-group cleanup proof timed out");
        assert!(
            fixture.was_reaped(),
            "post-handoff-take result was delivered before process-group cleanup proof"
        );
        let result = match delivered_during_cleanup {
            Some(result) => result,
            None => tokio::time::timeout(Duration::from_secs(1), &mut start)
                .await
                .expect("post-handoff-take result delivery timed out after cleanup proof"),
        };
        assert!(matches!(result, Err(SessionError::BackendUnavailable)));
        assert_eq!(manager.capacity.active(), (0, 0));
        assert_eq!(manager.supervisor_count_for_test(), 0);
        assert!(lifecycle.try_recv().is_err());
        let events = fixture.audit_events();
        assert_eq!(
            events
                .iter()
                .filter(|event| event["event_type"] == "session-started")
                .count(),
            1
        );
        let ended = events
            .iter()
            .filter(|event| event["event_type"] == "session-ended")
            .collect::<Vec<_>>();
        assert_eq!(ended.len(), 1);
        assert_eq!(ended[0]["close_reason"], "supervisor-unwind");
    }

    #[tokio::test]
    async fn cleanup_failure_quarantines_capacity_until_process_group_cleanup_is_proven() {
        for _ in 0..20 {
            let fixture = SshAdmissionFixture::with_blocked_cleanup(SshAdmissionScript::Pending);
            let manager = fixture.manager();
            let starting = {
                let manager = manager.clone();
                tokio::spawn(async move {
                    manager
                        .start(
                            Identity::new("alice").unwrap(),
                            "remote",
                            Resize::new(80, 24).unwrap(),
                        )
                        .await
                })
            };
            fixture.wait_spawned().await;
            starting.abort();
            let join_error = fixture_deadline(starting, "quarantined start join")
                .await
                .expect_err("aborted start task must be cancelled");
            assert!(join_error.is_cancelled());
            tokio::time::sleep(Duration::from_millis(400)).await;
            assert_eq!(manager.capacity.active(), (1, 1));
            assert_eq!(manager.supervisor_count_for_test(), 1);
            fixture.allow_cleanup();
            fixture.wait_reaped().await;
            assert_eq!(manager.capacity.active(), (0, 0));
            assert_eq!(manager.supervisor_count_for_test(), 0);
            let events = fixture.audit_events();
            assert_eq!(events.len(), 1);
            assert_eq!(events[0]["event_type"], "access-denied");
            assert_eq!(events[0]["category"], "target");
            assert_eq!(events[0]["reason"], "session-cancelled");
            assert!(
                events
                    .iter()
                    .all(|event| event["event_type"] != "session-started"
                        && event["event_type"] != "session-ended")
            );
        }
    }

    #[tokio::test]
    async fn admitted_cleanup_failure_quarantines_capacity_until_group_cleanup_is_proven() {
        for _ in 0..10 {
            let fixture =
                SshAdmissionFixture::with_blocked_cleanup(SshAdmissionScript::Authenticated);
            let manager = fixture.manager();
            let mut session = fixture_deadline(
                manager.start(
                    Identity::new("alice").unwrap(),
                    "remote",
                    Resize::new(80, 24).unwrap(),
                ),
                "authenticated session",
            )
            .await
            .unwrap();
            let closing = tokio::spawn(async move { session.close().await });
            tokio::time::sleep(Duration::from_millis(400)).await;
            assert_eq!(manager.capacity.active(), (1, 1));
            assert_eq!(manager.supervisor_count_for_test(), 1);

            fixture.allow_cleanup();
            let closed = fixture_deadline(closing, "quarantined close join")
                .await
                .unwrap()
                .unwrap();
            assert_eq!(closed.reason, SessionCloseReason::BackendFailure);
            fixture.wait_reaped().await;
            assert_eq!(manager.capacity.active(), (0, 0));
            assert_eq!(manager.supervisor_count_for_test(), 0);
        }
    }

    #[tokio::test]
    async fn natural_exit_cleanup_failure_keeps_connecting_capacity_quarantined() {
        let fixture =
            SshAdmissionFixture::with_blocked_cleanup(SshAdmissionScript::PendingThenExit(23));
        let manager = fixture.manager();
        let starting = {
            let manager = manager.clone();
            tokio::spawn(async move {
                manager
                    .start(
                        Identity::new("alice").unwrap(),
                        "remote",
                        Resize::new(80, 24).unwrap(),
                    )
                    .await
            })
        };
        fixture.wait_spawned().await;
        tokio::time::sleep(Duration::from_millis(400)).await;
        assert!(!starting.is_finished());
        assert_eq!(manager.capacity.active(), (1, 1));
        assert_eq!(manager.supervisor_count_for_test(), 1);

        fixture.allow_cleanup();
        assert!(matches!(
            fixture_deadline(starting, "natural connecting cleanup result")
                .await
                .unwrap(),
            Err(SessionError::SshFailed)
        ));
        fixture.wait_reaped().await;
        assert_eq!(manager.capacity.active(), (0, 0));
        assert_eq!(manager.supervisor_count_for_test(), 0);
    }

    #[tokio::test]
    async fn natural_exit_cleanup_failure_keeps_admitted_capacity_quarantined() {
        let fixture = SshAdmissionFixture::with_blocked_cleanup(
            SshAdmissionScript::AuthenticatedThenExit(23),
        );
        let manager = fixture.manager();
        let mut session = fixture_deadline(
            manager.start(
                Identity::new("alice").unwrap(),
                "remote",
                Resize::new(80, 24).unwrap(),
            ),
            "natural authenticated session",
        )
        .await
        .unwrap();
        let waiting = tokio::spawn(async move { session.wait_closed().await });
        tokio::time::sleep(Duration::from_millis(400)).await;
        assert!(!waiting.is_finished());
        assert_eq!(manager.capacity.active(), (1, 1));
        assert_eq!(manager.supervisor_count_for_test(), 1);

        fixture.allow_cleanup();
        let closed = fixture_deadline(waiting, "natural admitted cleanup result")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(closed.reason, SessionCloseReason::BackendFailure);
        assert_eq!(closed.outcome, Some(ChildOutcome::Code(23)));
        fixture.wait_reaped().await;
        assert_eq!(manager.capacity.active(), (0, 0));
        assert_eq!(manager.supervisor_count_for_test(), 0);
    }

    #[tokio::test]
    async fn shutdown_waits_for_quarantined_cleanup_owner_and_capacity_proof() {
        let fixture = SshAdmissionFixture::with_blocked_cleanup(SshAdmissionScript::Pending);
        let manager = fixture.manager();
        let starting = {
            let manager = manager.clone();
            tokio::spawn(async move {
                manager
                    .start(
                        Identity::new("alice").unwrap(),
                        "remote",
                        Resize::new(80, 24).unwrap(),
                    )
                    .await
            })
        };
        fixture.wait_spawned().await;
        let shutdown = {
            let manager = manager.clone();
            tokio::spawn(async move { manager.shutdown().await })
        };

        tokio::time::sleep(Duration::from_millis(400)).await;
        assert!(!shutdown.is_finished());
        assert_eq!(manager.capacity.active(), (1, 1));
        assert_eq!(manager.supervisor_count_for_test(), 1);

        fixture.allow_cleanup();
        fixture_deadline(shutdown, "quarantined shutdown join")
            .await
            .unwrap();
        assert!(matches!(
            fixture_deadline(starting, "quarantined start result")
                .await
                .unwrap(),
            Err(SessionError::ManagerClosed)
        ));
        fixture.wait_reaped().await;
        assert_eq!(manager.capacity.active(), (0, 0));
        assert_eq!(manager.supervisor_count_for_test(), 0);
    }

    #[tokio::test]
    async fn ssh_host_key_failure_has_one_denial_and_no_session_lifecycle() {
        assert_ssh_setup_denial(
            SshAdmissionScript::Failure(crate::ssh::SshDiagnosticClass::UnknownHostKey),
            SessionError::SshHostKeyFailed,
            "host-key",
            "unknown-host-key",
        )
        .await;
        assert_ssh_setup_denial(
            SshAdmissionScript::Failure(crate::ssh::SshDiagnosticClass::HostKeyMismatch),
            SessionError::SshHostKeyFailed,
            "host-key",
            "host-key-mismatch",
        )
        .await;
    }

    #[tokio::test]
    async fn ssh_connection_failure_has_one_denial_and_no_session_lifecycle() {
        assert_ssh_setup_denial(
            SshAdmissionScript::Failure(crate::ssh::SshDiagnosticClass::ConnectionFailed),
            SessionError::SshConnectionFailed,
            "target",
            "ssh-connection-failed",
        )
        .await;
    }

    #[tokio::test]
    async fn ssh_authentication_failure_has_one_denial_and_no_session_lifecycle() {
        assert_ssh_setup_denial(
            SshAdmissionScript::Failure(crate::ssh::SshDiagnosticClass::AuthenticationFailed),
            SessionError::SshAuthenticationFailed,
            "authentication",
            "ssh-authentication-failed",
        )
        .await;
    }

    #[tokio::test]
    async fn ssh_generic_setup_failure_has_one_denial_and_no_session_lifecycle() {
        assert_ssh_setup_denial(
            SshAdmissionScript::Failure(crate::ssh::SshDiagnosticClass::GenericFailure),
            SessionError::SshFailed,
            "target",
            "ssh-failed",
        )
        .await;
    }

    #[tokio::test]
    async fn ssh_admission_emits_created_running_and_one_correlated_start_only_after_authentication()
     {
        let fixture = SshAdmissionFixture::new(SshAdmissionScript::Pending);
        let manager = fixture.manager();
        let mut events = manager.subscribe_events();
        let starting = {
            let manager = manager.clone();
            tokio::spawn(async move {
                manager
                    .start(
                        Identity::new("alice").unwrap(),
                        "remote",
                        Resize::new(80, 24).unwrap(),
                    )
                    .await
            })
        };
        fixture.wait_spawned().await;
        assert!(events.try_recv().is_err());
        assert_eq!(fixture.audit_events().len(), 0);

        fixture.admit();
        let mut session = fixture_deadline(starting, "authenticated start join")
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(
            fixture_deadline(events.recv(), "created lifecycle event")
                .await
                .unwrap()
                .transition,
            LifecycleTransition::Created
        ));
        assert!(matches!(
            fixture_deadline(events.recv(), "running lifecycle event")
                .await
                .unwrap()
                .transition,
            LifecycleTransition::Running
        ));
        let audit = fixture.audit_events();
        assert_eq!(
            audit
                .iter()
                .filter(|event| event["event_type"] == "session-started")
                .count(),
            1
        );
        fixture_deadline(session.close(), "authenticated session close")
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn cancelled_ssh_setup_is_registered_terminated_reaped_and_releases_capacity() {
        for _ in 0..20 {
            let fixture = SshAdmissionFixture::new(SshAdmissionScript::Pending);
            let manager = fixture.manager();
            let starting = {
                let manager = manager.clone();
                tokio::spawn(async move {
                    manager
                        .start(
                            Identity::new("alice").unwrap(),
                            "remote",
                            Resize::new(80, 24).unwrap(),
                        )
                        .await
                })
            };
            fixture.wait_spawned().await;
            assert_eq!(manager.supervisor_count_for_test(), 1);
            starting.abort();
            let join_error = fixture_deadline(starting, "cancelled start join")
                .await
                .expect_err("aborted start task must be cancelled");
            assert!(join_error.is_cancelled());
            fixture.wait_reaped().await;
            assert_eq!(manager.capacity.active(), (0, 0));
            assert_eq!(manager.supervisor_count_for_test(), 0);
            let events = fixture.audit_events();
            assert_eq!(events.len(), 1);
            assert_eq!(events[0]["event_type"], "access-denied");
            assert_eq!(events[0]["category"], "target");
            assert_eq!(events[0]["reason"], "session-cancelled");
        }
    }

    #[tokio::test]
    async fn shutdown_during_ssh_setup_terminates_reaps_and_releases_capacity() {
        for _ in 0..20 {
            let fixture = SshAdmissionFixture::new(SshAdmissionScript::Pending);
            let manager = fixture.manager();
            let starting = {
                let manager = manager.clone();
                tokio::spawn(async move {
                    manager
                        .start(
                            Identity::new("alice").unwrap(),
                            "remote",
                            Resize::new(80, 24).unwrap(),
                        )
                        .await
                })
            };
            fixture.wait_spawned().await;
            fixture_deadline(manager.shutdown(), "connecting manager shutdown").await;
            assert!(matches!(
                fixture_deadline(starting, "shutdown start join")
                    .await
                    .unwrap(),
                Err(SessionError::ManagerClosed)
            ));
            assert!(fixture.was_reaped());
            assert_eq!(manager.capacity.active(), (0, 0));
        }
    }

    #[tokio::test]
    async fn audit_failure_during_ssh_setup_terminates_and_reaps_without_authority() {
        let fixture = SshAdmissionFixture::with_failing_audit(SshAdmissionScript::Pending);
        let manager = fixture.manager();
        let starting = {
            let manager = manager.clone();
            tokio::spawn(async move {
                manager
                    .start(
                        Identity::new("alice").unwrap(),
                        "remote",
                        Resize::new(80, 24).unwrap(),
                    )
                    .await
            })
        };
        fixture.wait_spawned().await;
        fixture.admit();
        assert!(matches!(
            fixture_deadline(starting, "audit failure start join")
                .await
                .unwrap(),
            Err(SessionError::AuditUnavailable)
        ));
        fixture.wait_reaped().await;
        assert_eq!(manager.capacity.active(), (0, 0));
        assert!(manager.subscribe_events().try_recv().is_err());
    }

    #[tokio::test]
    async fn ssh_remote_exit_status_is_not_connection_setup_failure() {
        let fixture = SshAdmissionFixture::new(SshAdmissionScript::AuthenticatedThenExit(23));
        let manager = fixture.manager();
        let mut session = fixture_deadline(
            manager.start(
                Identity::new("alice").unwrap(),
                "remote",
                Resize::new(80, 24).unwrap(),
            ),
            "authenticated remote-exit start",
        )
        .await
        .unwrap();
        let closed = fixture_deadline(session.wait_closed(), "authenticated remote exit")
            .await
            .unwrap();
        assert_eq!(closed.reason, SessionCloseReason::ChildExited);
        assert_eq!(closed.outcome, Some(ChildOutcome::Code(23)));
        assert!(
            fixture
                .audit_events()
                .iter()
                .all(|event| event["event_type"] != "access-denied")
        );
    }

    #[tokio::test]
    async fn existing_local_pty_lifecycle_is_unchanged() {
        let manager = manager(limits(4, 2), &[fixture_target(false)]);
        let mut session = manager
            .start(
                Identity::new("alice").unwrap(),
                "fixture",
                Resize::new(80, 24).unwrap(),
            )
            .await
            .unwrap();
        assert!(matches!(
            session.next_event().await.unwrap().transition,
            LifecycleTransition::Created
        ));
        assert!(matches!(
            session.next_event().await.unwrap().transition,
            LifecycleTransition::Running
        ));
        session.close().await.unwrap();
    }

    #[tokio::test]
    async fn allowlist_rejects_unknown_target_before_spawn() {
        let configured = fixture_target(false);
        let manager =
            SessionManager::new(limits(4, 2), allowlist(std::slice::from_ref(&configured)));
        assert!(matches!(
            manager
                .start(
                    Identity::new("alice").unwrap(),
                    "unknown",
                    Resize::new(80, 24).unwrap(),
                )
                .await,
            Err(SessionError::TargetUnavailable)
        ));
    }

    async fn session_read_until(session: &mut super::Session, marker: &[u8]) -> Vec<u8> {
        let mut output = Vec::new();
        tokio::time::timeout(Duration::from_secs(3), async {
            while !output.windows(marker.len()).any(|window| window == marker) {
                let chunk = session.read().await.expect("session output");
                output.extend_from_slice(&chunk);
            }
        })
        .await
        .expect("session output marker timed out");
        output
    }

    #[tokio::test]
    async fn io_session_echoes_opaque_output_and_propagates_resize() {
        let manager = manager(limits(4, 2), &[fixture_target(false)]);
        let mut session = manager
            .start(
                Identity::new("alice").unwrap(),
                "fixture",
                Resize::new(80, 24).unwrap(),
            )
            .await
            .unwrap();
        session_read_until(&mut session, b"INITIAL:24 80").await;
        session.resize(Resize::new(132, 41).unwrap()).await.unwrap();
        session.write(b"size\n".to_vec()).await.unwrap();
        session_read_until(&mut session, b"RESIZED:41 132").await;
        session.write(b"opaque-token\n".to_vec()).await.unwrap();
        session_read_until(&mut session, b"ECHO:opaque-token").await;
        session.close().await.unwrap();
    }

    #[tokio::test]
    async fn read_only_input_is_rejected_before_reaching_the_pty() {
        let manager = manager(limits(4, 2), &[fixture_target(true)]);
        let mut session = manager
            .start(
                Identity::new("alice").unwrap(),
                "fixture",
                Resize::new(80, 24).unwrap(),
            )
            .await
            .unwrap();
        session_read_until(&mut session, b"READY").await;
        assert_eq!(
            session.write(b"forbidden-token\n".to_vec()).await,
            Err(SessionError::ReadOnly)
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(100), session.read())
                .await
                .is_err()
        );
        session.close().await.unwrap();
    }

    #[tokio::test]
    async fn io_rejects_oversized_input_and_close_is_idempotent() {
        let manager = manager(limits(4, 2), &[fixture_target(false)]);
        let mut session = manager
            .start(
                Identity::new("alice").unwrap(),
                "fixture",
                Resize::new(80, 24).unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            session.write(vec![0; MAX_BINARY_BYTES + 1]).await,
            Err(SessionError::InputTooLarge)
        );
        let first = session.close().await.unwrap();
        let repeated = session.close().await.unwrap();
        assert_eq!(first, repeated);
    }

    #[tokio::test]
    async fn lifecycle_stream_has_exactly_created_running_closed() {
        let manager = manager(limits(4, 2), &[fixture_target(false)]);
        let mut session = manager
            .start(
                Identity::new("alice").unwrap(),
                "fixture",
                Resize::new(80, 24).unwrap(),
            )
            .await
            .unwrap();
        let created = session.next_event().await.unwrap();
        let running = session.next_event().await.unwrap();
        assert_eq!(created.transition, LifecycleTransition::Created);
        assert_eq!(running.transition, LifecycleTransition::Running);
        session.close().await.unwrap();
        let closed = session.next_event().await.unwrap();
        assert!(matches!(
            closed.transition,
            LifecycleTransition::Closed {
                reason: SessionCloseReason::Explicit,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn manager_audit_stream_survives_session_handle_drop() {
        let manager = manager(limits(4, 2), &[fixture_target(false)]);
        let mut audit = manager.subscribe_events();
        let session = manager
            .start(
                Identity::new("alice").unwrap(),
                "fixture",
                Resize::new(80, 24).unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            audit.recv().await.unwrap().transition,
            LifecycleTransition::Created
        );
        assert_eq!(
            audit.recv().await.unwrap().transition,
            LifecycleTransition::Running
        );
        drop(session);
        let closed = tokio::time::timeout(Duration::from_secs(3), audit.recv())
            .await
            .expect("audit close event timed out")
            .unwrap();
        assert!(matches!(
            closed.transition,
            LifecycleTransition::Closed {
                reason: SessionCloseReason::HandleDropped,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn manager_shutdown_awaits_supervisors_and_rejects_new_sessions() {
        let mut resistant = fixture_target(false);
        resistant.argv = vec!["ignore-hup".to_owned()];
        let manager = manager(limits(4, 2), &[resistant]);
        let _session = manager
            .start(
                Identity::new("alice").unwrap(),
                "fixture",
                Resize::new(80, 24).unwrap(),
            )
            .await
            .unwrap();
        manager.shutdown().await;
        assert!(matches!(
            manager
                .start(
                    Identity::new("bob").unwrap(),
                    "fixture",
                    Resize::new(80, 24).unwrap(),
                )
                .await,
            Err(SessionError::ManagerClosed)
        ));
    }

    #[tokio::test]
    async fn reserved_capacity_transfers_to_live_session_without_duplication() {
        let manager = manager(limits(1, 1), &[fixture_target(false)]);
        let identity = Identity::new("alice").unwrap();
        let reservation = manager
            .reserve(&identity, Instant::now() + Duration::from_secs(10))
            .await
            .unwrap();
        assert_eq!(manager.capacity.active(), (1, 1));

        let mut session = manager
            .start_reserved(
                reservation,
                identity,
                "fixture",
                Resize::new(80, 24).unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(manager.capacity.active(), (1, 1));
        session.close().await.unwrap();
        tokio::task::yield_now().await;
        assert_eq!(manager.capacity.active(), (0, 0));
    }

    #[tokio::test]
    async fn manager_shutdown_releases_outstanding_pending_reservations() {
        let manager = manager(limits(1, 1), &[fixture_target(false)]);
        let identity = Identity::new("alice").unwrap();
        let reservation = manager
            .reserve(&identity, Instant::now() + Duration::from_secs(10))
            .await
            .unwrap();
        let tickets = TicketStore::new(Duration::from_secs(10), 1);
        tickets
            .issue(identity, Target::Pty(fixture_target(false)), reservation)
            .unwrap();
        assert_eq!(manager.capacity.active(), (1, 1));

        manager.shutdown().await;
        assert_eq!(manager.capacity.active(), (0, 0));
        drop(tickets);
        assert_eq!(manager.capacity.active(), (0, 0));
    }

    #[tokio::test]
    async fn ticket_owned_pending_capacity_releases_during_unwind() {
        let manager = manager(limits(1, 1), &[fixture_target(false)]);
        let identity = Identity::new("alice").unwrap();
        let reservation = manager
            .reserve(&identity, Instant::now() + Duration::from_secs(10))
            .await
            .unwrap();
        let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let tickets = TicketStore::new(Duration::from_secs(10), 1);
            tickets
                .issue(
                    identity.clone(),
                    Target::Pty(fixture_target(false)),
                    reservation,
                )
                .unwrap();
            panic!("intentional ticket ownership unwind");
        }));
        assert!(unwound.is_err());
        assert_eq!(manager.capacity.active(), (0, 0));
        assert!(
            manager
                .reserve(&identity, Instant::now() + Duration::from_secs(10))
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn concurrent_start_and_shutdown_leave_no_unowned_supervisor() {
        let target = PtyTarget {
            name: "short".to_owned(),
            executable: "/usr/bin/true".into(),
            argv: Vec::new(),
            read_only: false,
        };
        for index in 0..20 {
            let manager = manager(limits(4, 2), std::slice::from_ref(&target));
            let starting = {
                let manager = manager.clone();
                tokio::spawn(async move {
                    manager
                        .start(
                            Identity::new(format!("user-{index}")).unwrap(),
                            "short",
                            Resize::new(80, 24).unwrap(),
                        )
                        .await
                })
            };
            let shutting_down = {
                let manager = manager.clone();
                tokio::spawn(async move { manager.shutdown().await })
            };
            let result = starting.await.unwrap();
            shutting_down.await.unwrap();
            drop(result);
            assert!(
                manager
                    .supervisors
                    .inner
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .active
                    .is_empty()
            );
        }
    }

    #[tokio::test]
    async fn invalid_resize_is_rejected_at_every_public_boundary() {
        let manager = manager(limits(4, 2), &[fixture_target(false)]);
        let invalid = Resize { cols: 0, rows: 24 };
        assert!(matches!(
            manager
                .start(Identity::new("alice").unwrap(), "fixture", invalid.clone())
                .await,
            Err(SessionError::InvalidResize)
        ));
        let mut session = manager
            .start(
                Identity::new("alice").unwrap(),
                "fixture",
                Resize::new(80, 24).unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            session.resize(invalid).await,
            Err(SessionError::InvalidResize)
        );
        session.close().await.unwrap();
    }

    #[tokio::test]
    async fn wait_closed_observes_natural_exit_without_overwriting_reason() {
        let manager = manager(limits(4, 2), &[fixture_target(false)]);
        let mut session = manager
            .start(
                Identity::new("alice").unwrap(),
                "fixture",
                Resize::new(80, 24).unwrap(),
            )
            .await
            .unwrap();
        session_read_until(&mut session, b"READY").await;
        session.write(b"exit\n".to_vec()).await.unwrap();
        let closed = session.wait_closed().await.unwrap();
        assert_eq!(closed.outcome, Some(ChildOutcome::Code(0)));
        assert!(matches!(
            closed.reason,
            SessionCloseReason::ChildExited | SessionCloseReason::BackendFailure
        ));
    }

    #[tokio::test]
    async fn io_output_remains_opaque_binary_data() {
        let binary = PtyTarget {
            name: "binary".to_owned(),
            executable: "/usr/bin/printf".into(),
            argv: vec!["\\377\\000X".to_owned()],
            read_only: false,
        };
        let manager = manager(limits(4, 2), std::slice::from_ref(&binary));
        let mut session = manager
            .start(
                Identity::new("alice").unwrap(),
                "binary",
                Resize::new(80, 24).unwrap(),
            )
            .await
            .unwrap();
        let output = tokio::time::timeout(Duration::from_secs(3), session.read())
            .await
            .unwrap()
            .unwrap();
        assert!(output.windows(3).any(|window| window == [0xff, 0x00, b'X']));
        session.wait_closed().await.unwrap();
    }

    #[tokio::test]
    async fn io_output_flood_is_bounded_and_close_remains_selectable() {
        let flood = PtyTarget {
            name: "flood".to_owned(),
            executable: "/usr/bin/yes".into(),
            argv: Vec::new(),
            read_only: false,
        };
        let manager = manager(limits(4, 2), std::slice::from_ref(&flood));
        let mut session = manager
            .start(
                Identity::new("alice").unwrap(),
                "flood",
                Resize::new(80, 24).unwrap(),
            )
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(3), async {
            while session.output_rx.len() < super::OUTPUT_CHANNEL_CAPACITY {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("bounded output queue did not fill");
        assert_eq!(session.output_rx.len(), super::OUTPUT_CHANNEL_CAPACITY);
        let closed = tokio::time::timeout(Duration::from_secs(3), session.close())
            .await
            .expect("close was blocked by output backpressure")
            .unwrap();
        assert_eq!(closed.reason, SessionCloseReason::Explicit);
    }

    #[tokio::test]
    async fn output_worker_failure_enters_supervised_backend_teardown() {
        let manager = manager(limits(4, 2), &[fixture_target(false)]);
        let mut session = manager
            .start(
                Identity::new("alice").unwrap(),
                "fixture",
                Resize::new(80, 24).unwrap(),
            )
            .await
            .unwrap();
        session_read_until(&mut session, b"READY").await;
        let (_replacement_tx, replacement_rx) = tokio::sync::mpsc::channel(1);
        let original_rx = std::mem::replace(&mut session.output_rx, replacement_rx);
        drop(original_rx);
        session.write(b"force-output\n".to_vec()).await.unwrap();
        let closed = tokio::time::timeout(Duration::from_secs(3), session.wait_closed())
            .await
            .expect("worker failure did not close session")
            .unwrap();
        assert_eq!(closed.reason, SessionCloseReason::BackendFailure);
    }

    #[tokio::test]
    async fn reservation_is_released_when_real_spawn_fails() {
        let identity = Identity::new("alice").unwrap();
        let mut missing = fixture_target(false);
        missing.name = "missing".to_owned();
        missing.executable = "/definitely/not/a/ttygate-program".into();
        let manager = manager(limits(1, 1), &[missing.clone(), fixture_target(false)]);
        assert!(matches!(
            manager
                .start(identity.clone(), "missing", Resize::new(80, 24).unwrap())
                .await,
            Err(SessionError::SpawnUnavailable)
        ));
        let mut session = manager
            .start(identity, "fixture", Resize::new(80, 24).unwrap())
            .await
            .expect("spawn failure must release reservation");
        session.close().await.unwrap();
    }

    async fn issue_reserved_ticket(
        manager: &SessionManager,
        identity: &Identity,
        target: Target,
    ) -> TicketGrant {
        let tickets = TicketStore::new(Duration::from_secs(10), 8);
        let reservation = manager
            .reserve(identity, Instant::now() + Duration::from_secs(10))
            .await
            .unwrap();
        let ticket = tickets
            .issue(identity.clone(), target, reservation)
            .unwrap();
        tickets.redeem(ticket.as_str(), identity).unwrap()
    }

    #[tokio::test]
    async fn ticket_owned_capacity_recovers_after_real_spawn_failure_exactly_once() {
        let identity = Identity::new("alice").unwrap();
        let mut missing = fixture_target(false);
        missing.name = "missing".to_owned();
        missing.executable = "/definitely/not/a/ttygate-program".into();
        let manager = manager(limits(1, 1), &[missing.clone(), fixture_target(false)]);
        let grant = issue_reserved_ticket(&manager, &identity, Target::Pty(missing)).await;
        let (target, reservation) = grant.into_parts();

        assert!(matches!(
            manager
                .start_reserved(
                    reservation,
                    identity.clone(),
                    target.name(),
                    Resize::new(80, 24).unwrap(),
                )
                .await,
            Err(SessionError::SpawnUnavailable)
        ));
        assert_eq!(manager.capacity.active(), (0, 0));
        assert!(
            manager
                .reserve(&identity, Instant::now() + Duration::from_secs(10))
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn ticket_owned_capacity_recovers_after_dropped_resistant_session() {
        let identity = Identity::new("alice").unwrap();
        let mut resistant = fixture_target(false);
        resistant.argv = vec!["ignore-hup".to_owned()];
        let manager = manager(limits(1, 1), std::slice::from_ref(&resistant));
        let grant = issue_reserved_ticket(&manager, &identity, Target::Pty(resistant)).await;
        let (target, reservation) = grant.into_parts();
        let session = manager
            .start_reserved(
                reservation,
                identity.clone(),
                target.name(),
                Resize::new(80, 24).unwrap(),
            )
            .await
            .unwrap();
        drop(session);
        tokio::time::timeout(Duration::from_secs(3), async {
            while manager.capacity.active() != (0, 0) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("dropped resistant session did not release ticket capacity");
        assert!(
            manager
                .reserve(&identity, Instant::now() + Duration::from_secs(10))
                .await
                .is_ok()
        );
    }

    async fn closed_event(session: &mut super::Session) -> LifecycleTransition {
        while let Some(event) = session.next_event().await {
            if matches!(event.transition, LifecycleTransition::Closed { .. }) {
                return event.transition;
            }
        }
        panic!("lifecycle stream ended before close");
    }

    #[tokio::test(start_paused = true)]
    async fn idle_timeout_resets_after_successful_activity() {
        tokio::time::resume();
        let manager = manager(
            Limits {
                idle_timeout: Duration::from_secs(10),
                absolute_timeout: Duration::from_secs(100),
                ..limits(4, 2)
            },
            &[fixture_target(false)],
        );
        let mut session = manager
            .start(
                Identity::new("alice").unwrap(),
                "fixture",
                Resize::new(80, 24).unwrap(),
            )
            .await
            .unwrap();
        session_read_until(&mut session, b"READY").await;
        tokio::time::pause();
        tokio::time::advance(Duration::from_secs(9)).await;
        session.resize(Resize::new(81, 24).unwrap()).await.unwrap();
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(9)).await;
        assert_eq!(session.state(), SessionState::Running);
        tokio::time::advance(Duration::from_millis(900)).await;
        assert_eq!(session.state(), SessionState::Running);
        tokio::time::resume();
        let transition = closed_event(&mut session).await;
        assert!(
            matches!(
                transition,
                LifecycleTransition::Closed {
                    reason: SessionCloseReason::Timeout(TimeoutKind::Idle),
                    ..
                }
            ),
            "{transition:?}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn absolute_timeout_is_independent_of_activity() {
        tokio::time::resume();
        let manager = manager(
            Limits {
                idle_timeout: Duration::from_secs(10),
                absolute_timeout: Duration::from_secs(10),
                ..limits(4, 2)
            },
            &[fixture_target(false)],
        );
        let mut session = manager
            .start(
                Identity::new("alice").unwrap(),
                "fixture",
                Resize::new(80, 24).unwrap(),
            )
            .await
            .unwrap();
        session_read_until(&mut session, b"READY").await;
        tokio::time::pause();
        for cols in 81..=84 {
            tokio::time::advance(Duration::from_secs(2)).await;
            session
                .resize(Resize::new(cols, 24).unwrap())
                .await
                .unwrap();
            tokio::task::yield_now().await;
        }
        tokio::time::advance(Duration::from_millis(1_900)).await;
        assert_eq!(session.state(), SessionState::Running);
        tokio::time::resume();
        let transition = closed_event(&mut session).await;
        assert!(
            matches!(
                transition,
                LifecycleTransition::Closed {
                    reason: SessionCloseReason::Timeout(TimeoutKind::Absolute),
                    ..
                }
            ),
            "{transition:?}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn rejected_read_only_input_does_not_reset_idle_timeout() {
        tokio::time::resume();
        let manager = manager(
            Limits {
                idle_timeout: Duration::from_secs(5),
                absolute_timeout: Duration::from_secs(50),
                ..limits(4, 2)
            },
            &[fixture_target(true)],
        );
        let mut session = manager
            .start(
                Identity::new("alice").unwrap(),
                "fixture",
                Resize::new(80, 24).unwrap(),
            )
            .await
            .unwrap();
        session_read_until(&mut session, b"READY").await;
        tokio::time::pause();
        tokio::time::advance(Duration::from_secs(4)).await;
        assert_eq!(
            session.write(b"rejected\n".to_vec()).await,
            Err(SessionError::ReadOnly)
        );
        tokio::time::advance(Duration::from_secs(1)).await;
        tokio::time::resume();
        let transition = closed_event(&mut session).await;
        assert!(
            matches!(
                transition,
                LifecycleTransition::Closed {
                    reason: SessionCloseReason::Timeout(TimeoutKind::Idle),
                    ..
                }
            ),
            "{transition:?}"
        );
    }

    #[tokio::test]
    async fn supervisor_unwind_reaps_child_and_has_exactly_one_audit_completion() {
        let directory = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
        let path = directory.path().join("audit.jsonl");
        let audit = Arc::new(AuditLog::open(&path).unwrap());
        let manager = SessionManager::new_with_audit(
            limits(4, 2),
            allowlist(&[fixture_target(false)]),
            audit,
        )
        .with_supervisor_panic_for_test();
        let mut session = manager
            .start(
                Identity::new("alice").unwrap(),
                "fixture",
                Resize::new(80, 24).unwrap(),
            )
            .await
            .unwrap();

        let closed = session.wait_closed().await.unwrap();
        assert_eq!(closed.reason, SessionCloseReason::SupervisorUnwind);
        manager.shutdown().await;

        let events = fs::read_to_string(path)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            events
                .iter()
                .filter(|event| event["event_type"] == "session-started")
                .count(),
            1
        );
        let ended = events
            .iter()
            .filter(|event| event["event_type"] == "session-ended")
            .collect::<Vec<_>>();
        assert_eq!(ended.len(), 1);
        assert_eq!(ended[0]["close_reason"], "supervisor-unwind");
    }
}
