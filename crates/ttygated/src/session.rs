use std::{os::unix::process::ExitStatusExt, time::SystemTime};

use thiserror::Error;

use crate::{protocol, ticket::Identity};

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

#[cfg(test)]
mod tests {
    use std::{
        os::unix::process::ExitStatusExt,
        time::{Duration, SystemTime},
    };

    use crate::ticket::Identity;

    use super::{
        ChildOutcome, LifecycleEvent, LifecycleTransition, SessionCloseReason, SessionError,
        SessionState, StateMachine, TimeoutKind,
    };

    #[test]
    fn dependency_surface_compiles() {
        let _ = pty_process::Size::new(24, 80);
        let _ = nix::sys::signal::Signal::SIGHUP;
        let _ = tokio::process::Command::new("/bin/true");
        let (_sender, _receiver) = tokio::sync::mpsc::channel::<Vec<u8>>(1);
        let _ = tokio::time::Duration::from_secs(1);
    }

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
}
