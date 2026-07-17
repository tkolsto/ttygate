#![cfg(unix)]

use std::{path::PathBuf, time::Duration};

use nix::{sys::signal::kill, unistd::Pid};
use tokio::time::timeout;
use ttygated::{
    config::{Limits, PtyTarget},
    protocol::Resize,
    session::{ChildOutcome, LifecycleTransition, Session, SessionCloseReason, SessionManager},
    ticket::Identity,
};

const WAIT: Duration = Duration::from_secs(3);

fn fixture_target(arguments: &[&str]) -> PtyTarget {
    PtyTarget {
        name: "lifecycle-fixture".to_owned(),
        executable: PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/pty_child.sh"),
        argv: arguments.iter().map(|value| (*value).to_owned()).collect(),
        read_only: false,
    }
}

fn limits(idle: Duration, absolute: Duration) -> Limits {
    Limits {
        max_sessions: 4,
        max_sessions_per_user: 2,
        idle_timeout: idle,
        absolute_timeout: absolute,
    }
}

async fn running_session(arguments: &[&str]) -> Session {
    SessionManager::new(limits(Duration::from_secs(60), Duration::from_secs(600)))
        .start(
            Identity::new("integration-user").unwrap(),
            fixture_target(arguments),
            Resize::new(80, 24).unwrap(),
        )
        .await
        .unwrap()
}

fn parse_pid(output: &[u8], key: &str) -> u32 {
    String::from_utf8_lossy(output)
        .lines()
        .find_map(|line| {
            line.trim()
                .strip_prefix(key)
                .and_then(|value| value.parse().ok())
        })
        .unwrap_or_else(|| panic!("missing {key} in {}", String::from_utf8_lossy(output)))
}

async fn process_ids(session: &mut Session) -> (u32, u32) {
    let mut output = Vec::new();
    timeout(WAIT, async {
        while !output
            .windows(b"READY".len())
            .any(|window| window == b"READY")
        {
            output.extend_from_slice(&session.read().await.unwrap());
        }
    })
    .await
    .expect("fixture did not become ready");
    (parse_pid(&output, "PID:"), parse_pid(&output, "DESC:"))
}

fn process_exists(pid: u32) -> bool {
    let Ok(pid) = i32::try_from(pid) else {
        return false;
    };
    match kill(Pid::from_raw(pid), None) {
        Ok(()) | Err(nix::errno::Errno::EPERM) => true,
        Err(nix::errno::Errno::ESRCH) => false,
        Err(error) => panic!("process probe failed: {error}"),
    }
}

async fn assert_absent(pid: u32) {
    timeout(WAIT, async {
        while process_exists(pid) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("process {pid} remained after teardown"));
}

async fn closed_transition(session: &mut Session) -> LifecycleTransition {
    timeout(WAIT, async {
        loop {
            if let Some(event) = session.next_event().await
                && matches!(event.transition, LifecycleTransition::Closed { .. })
            {
                break event.transition;
            }
        }
    })
    .await
    .expect("session did not emit closed event")
}

#[tokio::test]
async fn explicit_close_terminates_and_reaps_leader_and_descendant() {
    let mut session = running_session(&[]).await;
    let (leader, descendant) = process_ids(&mut session).await;
    let closed = session.close().await.unwrap();
    assert_eq!(closed.reason, SessionCloseReason::Explicit);
    assert_absent(leader).await;
    assert_absent(descendant).await;
}

#[tokio::test]
async fn dropped_session_terminates_and_reaps_process_group() {
    let mut session = running_session(&[]).await;
    let (leader, descendant) = process_ids(&mut session).await;
    drop(session);
    assert_absent(leader).await;
    assert_absent(descendant).await;
}

#[tokio::test]
async fn natural_leader_exit_still_terminates_descendant() {
    let mut session = running_session(&[]).await;
    let (leader, descendant) = process_ids(&mut session).await;
    session.write(b"exit\n".to_vec()).await.unwrap();
    let transition = closed_transition(&mut session).await;
    assert!(
        matches!(
            transition,
            LifecycleTransition::Closed {
                reason: SessionCloseReason::ChildExited | SessionCloseReason::BackendFailure,
                outcome: Some(ChildOutcome::Code(0)),
            }
        ),
        "{transition:?}"
    );
    assert_absent(leader).await;
    assert_absent(descendant).await;
}

#[tokio::test]
async fn hup_resistant_group_escalates_to_sigkill_and_is_reaped() {
    let mut session = running_session(&["ignore-hup"]).await;
    let (leader, descendant) = process_ids(&mut session).await;
    let closed = session.close().await.unwrap();
    assert_eq!(closed.reason, SessionCloseReason::Explicit);
    assert_eq!(closed.outcome, Some(ChildOutcome::Signal(9)));
    assert_absent(leader).await;
    assert_absent(descendant).await;
}

#[tokio::test]
async fn idle_timeout_terminates_and_reaps_process_group() {
    let manager = SessionManager::new(limits(Duration::from_millis(500), Duration::from_secs(2)));
    let mut session = manager
        .start(
            Identity::new("integration-user").unwrap(),
            fixture_target(&[]),
            Resize::new(80, 24).unwrap(),
        )
        .await
        .unwrap();
    let (leader, descendant) = process_ids(&mut session).await;
    let transition = closed_transition(&mut session).await;
    assert!(matches!(
        transition,
        LifecycleTransition::Closed {
            reason: SessionCloseReason::Timeout(_),
            ..
        }
    ));
    assert_absent(leader).await;
    assert_absent(descendant).await;
}

#[tokio::test]
async fn absolute_timeout_terminates_and_reaps_process_group() {
    let manager = SessionManager::new(limits(Duration::from_secs(2), Duration::from_millis(500)));
    let mut session = manager
        .start(
            Identity::new("integration-user").unwrap(),
            fixture_target(&[]),
            Resize::new(80, 24).unwrap(),
        )
        .await
        .unwrap();
    let (leader, descendant) = process_ids(&mut session).await;
    let transition = closed_transition(&mut session).await;
    assert!(matches!(
        transition,
        LifecycleTransition::Closed {
            reason: SessionCloseReason::Timeout(_),
            ..
        }
    ));
    assert_absent(leader).await;
    assert_absent(descendant).await;
}
