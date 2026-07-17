use std::{
    collections::HashMap,
    os::unix::process::ExitStatusExt,
    sync::{Arc, Mutex},
    time::SystemTime,
};

use thiserror::Error;

use crate::{config::Limits, protocol, ticket::Identity};

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
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "wired into the PTY supervisor in the next TDD batch"
        )
    )]
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
    #[error("The terminal backend is unavailable.")]
    BackendUnavailable,
    #[error("The terminal session is closed.")]
    Closed,
    #[error("The configured terminal is read-only.")]
    ReadOnly,
    #[error("The terminal input is too large.")]
    InputTooLarge,
    #[error("The session state transition is invalid.")]
    InvalidTransition,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "wired into the PTY supervisor in the next TDD batch"
    )
)]
struct TerminalState {
    state: SessionState,
    reason: SessionCloseReason,
    outcome: Option<ChildOutcome>,
}

#[derive(Debug)]
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "wired into the PTY supervisor in the next TDD batch"
    )
)]
struct StateMachine {
    state: SessionState,
    terminal: Option<TerminalState>,
}

#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "wired into the PTY supervisor in the next TDD batch"
    )
)]
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
    ) -> Result<TerminalState, SessionError> {
        if let Some(terminal) = self.terminal {
            return Ok(terminal);
        }
        if self.state != SessionState::Running {
            return Err(SessionError::InvalidTransition);
        }
        let terminal = TerminalState {
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
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "wired into SessionManager in the next TDD batch")
)]
struct Capacity {
    inner: Arc<CapacityInner>,
}

#[derive(Debug)]
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "wired into SessionManager in the next TDD batch")
)]
struct CapacityInner {
    max_sessions: usize,
    max_sessions_per_identity: usize,
    counts: Mutex<CapacityCounts>,
}

#[derive(Debug, Default)]
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "wired into SessionManager in the next TDD batch")
)]
struct CapacityCounts {
    total: usize,
    by_identity: HashMap<Identity, usize>,
}

#[cfg_attr(
    not(test),
    expect(dead_code, reason = "wired into SessionManager in the next TDD batch")
)]
impl Capacity {
    fn new(limits: &Limits) -> Self {
        Self {
            inner: Arc::new(CapacityInner {
                max_sessions: limits.max_sessions,
                max_sessions_per_identity: limits.max_sessions_per_user,
                counts: Mutex::new(CapacityCounts::default()),
            }),
        }
    }

    fn reserve(&self, identity: &Identity) -> Result<Reservation, SessionError> {
        let mut counts = self
            .inner
            .counts
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if counts.total >= self.inner.max_sessions {
            return Err(SessionError::GlobalLimit);
        }
        let identity_count = counts.by_identity.get(identity).copied().unwrap_or(0);
        if identity_count >= self.inner.max_sessions_per_identity {
            return Err(SessionError::IdentityLimit);
        }
        counts.total += 1;
        counts
            .by_identity
            .insert(identity.clone(), identity_count + 1);
        Ok(Reservation {
            capacity: Arc::clone(&self.inner),
            identity: Some(identity.clone()),
        })
    }

    #[cfg(test)]
    fn active(&self) -> (usize, usize) {
        let counts = self
            .inner
            .counts
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        (
            counts.total,
            counts.by_identity.values().copied().max().unwrap_or(0),
        )
    }
}

#[derive(Debug)]
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "wired into SessionManager in the next TDD batch")
)]
struct Reservation {
    capacity: Arc<CapacityInner>,
    identity: Option<Identity>,
}

impl Drop for Reservation {
    fn drop(&mut self) {
        let Some(identity) = self.identity.take() else {
            return;
        };
        let mut counts = self
            .capacity
            .counts
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        counts.total = counts
            .total
            .checked_sub(1)
            .expect("a live reservation contributes to total");
        let remove_identity = {
            let identity_count = counts
                .by_identity
                .get_mut(&identity)
                .expect("a live reservation contributes to its identity");
            *identity_count = identity_count
                .checked_sub(1)
                .expect("a live reservation has a positive identity count");
            *identity_count == 0
        };
        if remove_identity {
            counts.by_identity.remove(&identity);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        os::unix::process::ExitStatusExt,
        sync::{Arc, Barrier},
        thread,
        time::{Duration, SystemTime},
    };

    use crate::{config::Limits, ticket::Identity};

    use super::{
        Capacity, ChildOutcome, LifecycleEvent, LifecycleTransition, SessionCloseReason,
        SessionError, SessionState, StateMachine, TimeoutKind,
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
            SessionError::BackendUnavailable,
            SessionError::Closed,
            SessionError::ReadOnly,
            SessionError::InputTooLarge,
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
}
