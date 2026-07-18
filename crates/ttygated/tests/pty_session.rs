#![cfg(unix)]

use std::{fs, path::PathBuf, sync::Arc, time::Duration};

use nix::{
    sys::signal::{Signal, kill, killpg},
    unistd::Pid,
};
use tokio::time::timeout;
use ttygated::{
    audit::AuditLog,
    config::{Limits, PtyTarget, Target, TargetAllowlist},
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
        session_requests_per_window: 10,
        session_request_window: Duration::from_secs(60),
        authentication_failures_per_window: 20,
        authentication_failure_window: Duration::from_secs(60),
    }
}

async fn running_session(arguments: &[&str]) -> Session {
    let target = fixture_target(arguments);
    SessionManager::new(
        limits(Duration::from_secs(60), Duration::from_secs(600)),
        TargetAllowlist::new(vec![Target::Pty(target.clone())]).unwrap(),
    )
    .start(
        Identity::new("integration-user").unwrap(),
        "lifecycle-fixture",
        Resize::new(80, 24).unwrap(),
    )
    .await
    .unwrap()
}

fn audited_manager(
    arguments: &[&str],
    idle: Duration,
    absolute: Duration,
) -> (tempfile::TempDir, PathBuf, SessionManager) {
    let directory = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
    let path = directory.path().join("audit.jsonl");
    let target = fixture_target(arguments);
    let manager = SessionManager::new_with_audit(
        limits(idle, absolute),
        TargetAllowlist::new(vec![Target::Pty(target)]).unwrap(),
        Arc::new(AuditLog::open(&path).unwrap()),
    );
    (directory, path, manager)
}

async fn assert_one_audit_completion(path: &PathBuf, expected_reason: &str) {
    let events = timeout(WAIT, async {
        loop {
            let events = fs::read_to_string(path)
                .unwrap()
                .lines()
                .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
                .collect::<Vec<_>>();
            if events
                .iter()
                .any(|event| event["event_type"] == "session-ended")
            {
                break events;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("audit completion timed out");
    let started = events
        .iter()
        .filter(|event| event["event_type"] == "session-started")
        .collect::<Vec<_>>();
    let ended = events
        .iter()
        .filter(|event| event["event_type"] == "session-ended")
        .collect::<Vec<_>>();
    assert_eq!(started.len(), 1);
    assert_eq!(ended.len(), 1);
    assert_eq!(started[0]["session_id"], ended[0]["session_id"]);
    assert_eq!(ended[0]["close_reason"], expected_reason);
}

struct ProcessGroupGuard {
    leader: u32,
    armed: bool,
}

impl ProcessGroupGuard {
    fn new(leader: u32) -> Self {
        Self {
            leader,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for ProcessGroupGuard {
    fn drop(&mut self) {
        if self.armed
            && let Ok(pid) = i32::try_from(self.leader)
        {
            let _ = killpg(Pid::from_raw(pid), Signal::SIGKILL);
        }
    }
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

fn process_group_exists(process_group: u32) -> bool {
    let process_group = i32::try_from(process_group).expect("fixture PGID fits i32");
    match killpg(Pid::from_raw(process_group), None) {
        Ok(()) | Err(nix::errno::Errno::EPERM) => true,
        Err(nix::errno::Errno::ESRCH) => false,
        Err(error) => panic!("process-group probe failed: {error}"),
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
    let mut guard = ProcessGroupGuard::new(leader);
    let closed = session.close().await.unwrap();
    assert_eq!(closed.reason, SessionCloseReason::Explicit);
    assert_absent(leader).await;
    assert_absent(descendant).await;
    guard.disarm();
}

#[tokio::test]
async fn dropped_session_terminates_and_reaps_process_group() {
    let mut session = running_session(&[]).await;
    let (leader, descendant) = process_ids(&mut session).await;
    let mut guard = ProcessGroupGuard::new(leader);
    drop(session);
    assert_absent(leader).await;
    assert_absent(descendant).await;
    guard.disarm();
}

#[tokio::test]
async fn normal_exit_has_exactly_one_audit_completion() {
    let (_directory, path, manager) = audited_manager(
        &["natural-resistant"],
        Duration::from_secs(60),
        Duration::from_secs(600),
    );
    let mut session = manager
        .start(
            Identity::new("integration-user").unwrap(),
            "lifecycle-fixture",
            Resize::new(80, 24).unwrap(),
        )
        .await
        .unwrap();
    let (leader, descendant) = process_ids(&mut session).await;
    let mut guard = ProcessGroupGuard::new(leader);
    session.write(b"exit\n".to_vec()).await.unwrap();
    let transition = closed_transition(&mut session).await;
    assert!(matches!(
        transition,
        LifecycleTransition::Closed {
            reason: SessionCloseReason::ChildExited,
            outcome: Some(ChildOutcome::Code(0)),
        }
    ));
    assert_absent(leader).await;
    assert_absent(descendant).await;
    assert_one_audit_completion(&path, "child-exited").await;
    guard.disarm();
}

#[tokio::test]
async fn resistant_child_cleanup_has_exactly_one_audit_completion() {
    let (_directory, path, manager) = audited_manager(
        &["ignore-hup"],
        Duration::from_secs(60),
        Duration::from_secs(600),
    );
    let mut session = manager
        .start(
            Identity::new("integration-user").unwrap(),
            "lifecycle-fixture",
            Resize::new(80, 24).unwrap(),
        )
        .await
        .unwrap();
    let (leader, descendant) = process_ids(&mut session).await;
    let mut guard = ProcessGroupGuard::new(leader);
    let closed = session.close().await.unwrap();
    assert_eq!(closed.reason, SessionCloseReason::Explicit);
    assert_eq!(closed.outcome, Some(ChildOutcome::Signal(9)));
    assert_absent(leader).await;
    assert_absent(descendant).await;
    assert_one_audit_completion(&path, "explicit").await;
    guard.disarm();
}

#[tokio::test]
async fn idle_timeout_has_exactly_one_audit_completion() {
    let (_directory, path, manager) =
        audited_manager(&[], Duration::from_millis(500), Duration::from_secs(2));
    let mut session = manager
        .start(
            Identity::new("integration-user").unwrap(),
            "lifecycle-fixture",
            Resize::new(80, 24).unwrap(),
        )
        .await
        .unwrap();
    let (leader, descendant) = process_ids(&mut session).await;
    let mut guard = ProcessGroupGuard::new(leader);
    let transition = closed_transition(&mut session).await;
    assert!(matches!(
        transition,
        LifecycleTransition::Closed {
            reason: SessionCloseReason::Timeout(ttygated::session::TimeoutKind::Idle),
            ..
        }
    ));
    assert_absent(leader).await;
    assert_absent(descendant).await;
    assert_one_audit_completion(&path, "idle-timeout").await;
    guard.disarm();
}

#[tokio::test]
async fn absolute_timeout_has_exactly_one_audit_completion() {
    let (_directory, path, manager) =
        audited_manager(&[], Duration::from_secs(2), Duration::from_millis(500));
    let mut session = manager
        .start(
            Identity::new("integration-user").unwrap(),
            "lifecycle-fixture",
            Resize::new(80, 24).unwrap(),
        )
        .await
        .unwrap();
    let (leader, descendant) = process_ids(&mut session).await;
    let mut guard = ProcessGroupGuard::new(leader);
    let transition = closed_transition(&mut session).await;
    assert!(matches!(
        transition,
        LifecycleTransition::Closed {
            reason: SessionCloseReason::Timeout(ttygated::session::TimeoutKind::Absolute),
            ..
        }
    ));
    assert_absent(leader).await;
    assert_absent(descendant).await;
    assert_one_audit_completion(&path, "absolute-timeout").await;
    guard.disarm();
}

#[tokio::test]
async fn manager_shutdown_has_exactly_one_audit_completion() {
    let (_directory, path, manager) = audited_manager(
        &["ignore-hup"],
        Duration::from_secs(60),
        Duration::from_secs(600),
    );
    let mut audit = manager.subscribe_events();
    let mut session = manager
        .start(
            Identity::new("integration-user").unwrap(),
            "lifecycle-fixture",
            Resize::new(80, 24).unwrap(),
        )
        .await
        .unwrap();
    let (leader, descendant) = process_ids(&mut session).await;
    let mut guard = ProcessGroupGuard::new(leader);
    manager.shutdown().await;
    assert_absent(leader).await;
    assert_absent(descendant).await;
    let closed = timeout(WAIT, async {
        loop {
            let event = audit.recv().await.unwrap();
            if matches!(event.transition, LifecycleTransition::Closed { .. }) {
                break event.transition;
            }
        }
    })
    .await
    .expect("manager audit close event timed out");
    assert!(matches!(
        closed,
        LifecycleTransition::Closed {
            reason: SessionCloseReason::ManagerShutdown,
            ..
        }
    ));
    assert_one_audit_completion(&path, "manager-shutdown").await;
    guard.disarm();
}

#[tokio::test]
async fn cancelled_shutdown_keeps_supervisors_owned_until_next_shutdown() {
    let target = fixture_target(&["ignore-hup"]);
    let manager = SessionManager::new(
        limits(Duration::from_secs(60), Duration::from_secs(600)),
        TargetAllowlist::new(vec![Target::Pty(target)]).unwrap(),
    );
    let mut session = manager
        .start(
            Identity::new("integration-user").unwrap(),
            "lifecycle-fixture",
            Resize::new(80, 24).unwrap(),
        )
        .await
        .unwrap();
    let (leader, descendant) = process_ids(&mut session).await;
    let mut guard = ProcessGroupGuard::new(leader);
    let interrupted = {
        let manager = manager.clone();
        tokio::spawn(async move { manager.shutdown().await })
    };
    tokio::time::sleep(Duration::from_millis(20)).await;
    interrupted.abort();
    assert!(interrupted.await.unwrap_err().is_cancelled());
    manager.shutdown().await;
    assert_absent(leader).await;
    assert_absent(descendant).await;
    guard.disarm();
}

#[tokio::test]
async fn cancelled_caller_has_exactly_one_audit_completion() {
    let (_directory, path, manager) = audited_manager(
        &["flood"],
        Duration::from_secs(60),
        Duration::from_secs(600),
    );
    let mut session = manager
        .start(
            Identity::new("integration-user").unwrap(),
            "lifecycle-fixture",
            Resize::new(80, 24).unwrap(),
        )
        .await
        .unwrap();
    let (leader, descendant) = process_ids(&mut session).await;
    let mut guard = ProcessGroupGuard::new(leader);
    tokio::time::sleep(Duration::from_millis(200)).await;
    let owner = tokio::spawn(async move {
        let _session = session;
        std::future::pending::<()>().await;
    });
    owner.abort();
    assert!(owner.await.unwrap_err().is_cancelled());
    assert_absent(leader).await;
    assert_absent(descendant).await;
    assert_one_audit_completion(&path, "cancellation").await;
    guard.disarm();
}

#[tokio::test]
async fn capacity_is_held_until_resistant_group_teardown_finishes() {
    let target = fixture_target(&["ignore-hup"]);
    let manager = SessionManager::new(
        Limits {
            max_sessions: 1,
            max_sessions_per_user: 1,
            idle_timeout: Duration::from_secs(60),
            absolute_timeout: Duration::from_secs(600),
            session_requests_per_window: 10,
            session_request_window: Duration::from_secs(60),
            authentication_failures_per_window: 20,
            authentication_failure_window: Duration::from_secs(60),
        },
        TargetAllowlist::new(vec![Target::Pty(target)]).unwrap(),
    );
    let mut first = manager
        .start(
            Identity::new("first").unwrap(),
            "lifecycle-fixture",
            Resize::new(80, 24).unwrap(),
        )
        .await
        .unwrap();
    let (leader, descendant) = process_ids(&mut first).await;
    let mut guard = ProcessGroupGuard::new(leader);
    let closing = tokio::spawn(async move { first.close().await.unwrap() });
    tokio::task::yield_now().await;
    assert!(matches!(
        manager
            .start(
                Identity::new("second").unwrap(),
                "lifecycle-fixture",
                Resize::new(80, 24).unwrap(),
            )
            .await,
        Err(ttygated::session::SessionError::GlobalLimit)
    ));
    assert_eq!(closing.await.unwrap().reason, SessionCloseReason::Explicit);
    assert!(
        !process_exists(leader),
        "leader remained after capacity release"
    );
    assert!(
        !process_exists(descendant),
        "descendant remained after capacity release"
    );
    assert!(
        !process_group_exists(leader),
        "process group remained after capacity release"
    );
    let mut second = manager
        .start(
            Identity::new("second").unwrap(),
            "lifecycle-fixture",
            Resize::new(80, 24).unwrap(),
        )
        .await
        .expect("capacity must release only after teardown");
    second.close().await.unwrap();
    guard.disarm();
}
