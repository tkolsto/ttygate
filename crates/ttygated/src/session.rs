use std::{
    collections::HashMap,
    os::unix::process::ExitStatusExt,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime},
};

use thiserror::Error;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::{Notify, broadcast, mpsc, oneshot, watch},
    task::JoinHandle,
    time::{Instant, sleep_until},
};

use crate::{
    config::{Limits, PtyTarget, Target, TargetAllowlist},
    protocol::{self, MAX_BINARY_BYTES, Resize},
    pty_backend::{BackendError, PtyProcessBackend, RunningPty},
    ticket::Identity,
};

const INPUT_CHANNEL_CAPACITY: usize = 8;
const OUTPUT_CHANNEL_CAPACITY: usize = 8;
const LIFECYCLE_CHANNEL_CAPACITY: usize = 3;
const AUDIT_CHANNEL_CAPACITY: usize = 64;
const CLEANUP_GRACE: Duration = Duration::from_millis(150);
const CHILD_EXIT_SETTLE: Duration = Duration::from_millis(250);
const WORKER_JOIN_TIMEOUT: Duration = Duration::from_secs(1);

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
    HandleDropped,
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

trait Backend: Send + Sync {
    fn spawn(&self, target: &PtyTarget, size: Resize) -> Result<RunningPty, BackendError>;
}

impl Backend for PtyProcessBackend {
    fn spawn(&self, target: &PtyTarget, size: Resize) -> Result<RunningPty, BackendError> {
        Self::spawn(target, size)
    }
}

#[derive(Clone)]
pub struct SessionManager {
    limits: Limits,
    capacity: Arc<Capacity>,
    backend: Arc<dyn Backend>,
    targets: Arc<TargetAllowlist>,
    supervisors: Arc<SupervisorRegistry>,
    audit_tx: broadcast::Sender<LifecycleEvent>,
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
        let (audit_tx, _) = broadcast::channel(AUDIT_CHANNEL_CAPACITY);
        Self {
            capacity: Arc::new(Capacity::new(&limits)),
            limits,
            backend: Arc::new(PtyProcessBackend),
            targets: Arc::new(targets),
            supervisors: Arc::new(SupervisorRegistry::default()),
            audit_tx,
        }
    }

    pub fn subscribe_events(&self) -> broadcast::Receiver<LifecycleEvent> {
        self.audit_tx.subscribe()
    }

    pub async fn start(
        &self,
        identity: Identity,
        target_name: &str,
        initial_size: Resize,
    ) -> Result<Session, SessionError> {
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
        let target = match self.targets.resolve(target_name) {
            Ok(Target::Pty(configured)) => configured.clone(),
            Ok(Target::Ssh(_)) | Err(_) => return Err(SessionError::TargetUnavailable),
        };
        validate_resize(&initial_size)?;
        let reservation = self.capacity.reserve(&identity)?;
        self.start_admitted(identity, target, initial_size, reservation)
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
        let target = match self.targets.resolve(target_name) {
            Ok(Target::Pty(configured)) => configured.clone(),
            Ok(Target::Ssh(_)) | Err(_) => return Err(SessionError::TargetUnavailable),
        };
        validate_resize(&initial_size)?;
        let reservation = reservation.activate(&identity)?;
        self.start_admitted(identity, target, initial_size, reservation)
    }

    fn start_admitted(
        &self,
        identity: Identity,
        target: PtyTarget,
        initial_size: Resize,
        reservation: Reservation,
    ) -> Result<Session, SessionError> {
        let created_at = Instant::now();
        let mut state = StateMachine::new();
        let (event_tx, event_rx) = mpsc::channel(LIFECYCLE_CHANNEL_CAPACITY);

        let running = self
            .backend
            .spawn(&target, initial_size)
            .map_err(|_| SessionError::SpawnUnavailable)?;
        state.start()?;
        debug_assert_eq!(state.state(), SessionState::Running);
        for transition in [LifecycleTransition::Created, LifecycleTransition::Running] {
            let event = lifecycle_event(&identity, &target, transition);
            event_tx
                .try_send(event.clone())
                .expect("lifecycle channel holds every possible transition");
            let _ = self.audit_tx.send(event);
        }

        let (command_tx, command_rx) = mpsc::channel(INPUT_CHANNEL_CAPACITY);
        let (output_tx, output_rx) = mpsc::channel(OUTPUT_CHANNEL_CAPACITY);
        let (close_tx, close_rx) = watch::channel(None);
        let (cancel_tx, cancel_rx) = watch::channel(false);
        let (activity_tx, activity_rx) = watch::channel(created_at);
        let (final_tx, final_rx) = watch::channel(None);
        let (worker_event_tx, worker_event_rx) = mpsc::channel(2);
        let (reader, writer, child) = running.into_parts();

        let reader_task = tokio::spawn(read_output(
            reader,
            output_tx,
            cancel_rx.clone(),
            activity_tx.clone(),
            worker_event_tx.clone(),
        ));
        let writer_task = tokio::spawn(write_input(
            writer,
            command_rx,
            cancel_rx,
            activity_tx,
            worker_event_tx,
            target.read_only,
        ));
        let supervisor = Supervisor {
            state,
            identity,
            target_name: target.name,
            limits: self.limits.clone(),
            created_at,
            reservation,
            child,
            close_rx,
            cancel_tx,
            activity_rx,
            final_tx,
            event_tx,
            audit_tx: self.audit_tx.clone(),
            worker_event_rx,
            reader_task,
            writer_task,
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
                supervise(supervisor).await;
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

        Ok(Session {
            command_tx,
            output_rx,
            close_tx,
            final_rx,
            event_rx,
            read_only: target.read_only,
        })
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
    target: &PtyTarget,
    transition: LifecycleTransition,
) -> LifecycleEvent {
    LifecycleEvent {
        identity: identity.clone(),
        target: target.name.clone(),
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
    reader_task: JoinHandle<()>,
    writer_task: JoinHandle<()>,
}

async fn supervise(mut supervisor: Supervisor) {
    let absolute_deadline = supervisor.created_at + supervisor.limits.absolute_timeout;
    let idle_deadline = supervisor.created_at + supervisor.limits.idle_timeout;
    let absolute_sleep = sleep_until(absolute_deadline);
    let idle_sleep = sleep_until(idle_deadline);
    tokio::pin!(absolute_sleep);
    tokio::pin!(idle_sleep);

    let (mut reason, natural_status) = loop {
        tokio::select! {
            biased;
            _ = &mut absolute_sleep => {
                break (SessionCloseReason::Timeout(TimeoutKind::Absolute), None);
            }
            status = supervisor.child.wait() => {
                break match status {
                    Ok(status) => (SessionCloseReason::ChildExited, Some(status)),
                    Err(_) => (SessionCloseReason::BackendFailure, None),
                };
            }
            changed = supervisor.close_rx.changed() => {
                let requested = if changed.is_err() {
                    SessionCloseReason::HandleDropped
                } else {
                    (*supervisor.close_rx.borrow_and_update())
                        .unwrap_or(SessionCloseReason::HandleDropped)
                };
                break (requested, None);
            }
            changed = supervisor.activity_rx.changed() => {
                if changed.is_ok() {
                    let last_activity = *supervisor.activity_rx.borrow_and_update();
                    idle_sleep.as_mut().reset(last_activity + supervisor.limits.idle_timeout);
                }
            }
            _ = &mut idle_sleep => {
                break (SessionCloseReason::Timeout(TimeoutKind::Idle), None);
            }
            worker = supervisor.worker_event_rx.recv() => {
                let _ = worker;
                break match tokio::time::timeout(
                    CHILD_EXIT_SETTLE,
                    supervisor.child.wait(),
                ).await {
                    Ok(Ok(status)) => (SessionCloseReason::ChildExited, Some(status)),
                    Ok(Err(_)) | Err(_) => (SessionCloseReason::BackendFailure, None),
                };
            }
        }
    };

    supervisor.cancel_tx.send_replace(true);
    let outcome = if let Some(status) = natural_status {
        if supervisor
            .child
            .cleanup_group_after_exit(CLEANUP_GRACE)
            .await
            .is_err()
        {
            reason = SessionCloseReason::BackendFailure;
        }
        Some(ChildOutcome::from_status(status))
    } else {
        match supervisor.child.terminate(CLEANUP_GRACE).await {
            Ok(status) => Some(ChildOutcome::from_status(status)),
            Err(_) => {
                reason = SessionCloseReason::BackendFailure;
                None
            }
        }
    };

    join_worker(supervisor.reader_task).await;
    join_worker(supervisor.writer_task).await;
    let closed = supervisor
        .state
        .close(reason, outcome)
        .expect("supervisor closes a running session exactly once");
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
        os::unix::process::ExitStatusExt,
        sync::{Arc, Barrier, Mutex as StdMutex},
        thread,
        time::{Duration, SystemTime},
    };

    use crate::{
        config::{Limits, PtyTarget, Target, TargetAllowlist},
        protocol::{MAX_BINARY_BYTES, Resize},
        ticket::{Identity, TicketGrant, TicketStore},
    };
    use tokio::time::Instant;

    use super::{
        Capacity, ChildOutcome, LifecycleEvent, LifecycleTransition, SessionCloseReason,
        SessionError, SessionManager, SessionState, StateMachine, TimeoutKind,
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
            SessionCloseReason::HandleDropped,
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
}
