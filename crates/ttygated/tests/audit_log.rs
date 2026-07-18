use std::{
    fs,
    net::SocketAddr,
    sync::{Arc, Barrier},
    thread,
    time::{Duration, SystemTime},
};

use ttygated::{
    audit::{
        AuditError, AuditEvent, AuditLog, AuditTimestamp, CorrelationId, DenialCategory,
        DenialReason, SessionId,
    },
    config::{Limits, PtyTarget, Target, TargetAllowlist},
    protocol::Resize,
    session::{SessionCloseReason, SessionError, SessionManager},
    ticket::Identity,
};

fn timestamp(seconds: u64) -> AuditTimestamp {
    AuditTimestamp::from_system_time(SystemTime::UNIX_EPOCH + Duration::from_secs(seconds)).unwrap()
}

#[test]
fn audit_v1_serialization_is_exact() {
    let identity = Identity::new("alice").unwrap();
    let event = AuditEvent::session_started(
        SessionId::from_bytes([7; 16]),
        &identity,
        "admin-shell",
        Some("127.0.0.1:43123".parse::<SocketAddr>().unwrap()),
        timestamp(0),
    );

    assert_eq!(
        serde_json::to_string(&event).unwrap(),
        concat!(
            r#"{"schema_version":1,"event_type":"session-started","#,
            r#""session_id":"BwcHBwcHBwcHBwcHBwcHBw","identity":"alice","#,
            r#""target":"admin-shell","remote_address":"127.0.0.1:43123","#,
            r#""started_at":"1970-01-01T00:00:00Z"}"#
        )
    );
}

#[test]
fn audit_json_escapes_newlines_without_record_injection() {
    let identity = Identity::new("alice\"\\operator").unwrap();
    let event = AuditEvent::authentication_succeeded(
        &identity,
        Some("[::1]:43123".parse().unwrap()),
        timestamp(1),
    );

    let encoded = serde_json::to_string(&event).unwrap();

    assert_eq!(encoded.lines().count(), 1);
    assert!(encoded.contains(r#""identity":"alice\"\\operator""#));
    assert!(!encoded.contains('\n'));
}

#[test]
fn audit_schema_can_represent_future_host_key_denial() {
    let event = AuditEvent::access_denied(
        CorrelationId::from_bytes([9; 16]),
        DenialCategory::HostKey,
        DenialReason::HostKeyVerificationFailed,
        None,
        None,
        Some("192.0.2.10:2222".parse().unwrap()),
        timestamp(2),
    );

    let value = serde_json::to_value(event).unwrap();

    assert_eq!(value["schema_version"], 1);
    assert_eq!(value["event_type"], "access-denied");
    assert_eq!(value["category"], "host-key");
    assert_eq!(value["reason"], "host-key-verification-failed");
    assert!(value.get("identity").is_none());
    assert!(value.get("target").is_none());
}

#[test]
fn audit_event_types_have_no_terminal_or_secret_fields() {
    let identity = Identity::new("alice").unwrap();
    let events = [
        AuditEvent::authentication_succeeded(&identity, None, timestamp(3)),
        AuditEvent::session_started(
            SessionId::from_bytes([1; 16]),
            &identity,
            "shell",
            None,
            timestamp(4),
        ),
        AuditEvent::access_denied(
            CorrelationId::from_bytes([2; 16]),
            DenialCategory::Ticket,
            DenialReason::TicketMalformed,
            Some(&identity),
            None,
            None,
            timestamp(5),
        ),
    ];

    for event in events {
        let object = serde_json::to_value(event)
            .unwrap()
            .as_object()
            .unwrap()
            .clone();
        for forbidden in [
            "terminal_input",
            "terminal_output",
            "cookie",
            "ticket",
            "authorization",
            "headers",
            "request_body",
            "command",
            "arguments",
            "environment",
            "error",
        ] {
            assert!(!object.contains_key(forbidden), "{forbidden}");
        }
    }
}

fn denial(sequence: u8) -> AuditEvent {
    AuditEvent::access_denied(
        CorrelationId::from_bytes([sequence; 16]),
        DenialCategory::Authentication,
        DenialReason::IdentityRequired,
        None,
        None,
        Some("127.0.0.1:4000".parse().unwrap()),
        timestamp(u64::from(sequence)),
    )
}

fn audit_values(path: &std::path::Path) -> Vec<serde_json::Value> {
    fs::read_to_string(path)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

#[test]
fn audit_open_creates_restrictive_literal_destination() {
    use std::os::unix::fs::PermissionsExt;

    let directory = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
    let path = directory.path().join("literal-audit.jsonl");
    let log = AuditLog::open(&path).unwrap();

    log.record(&denial(1)).unwrap();

    assert!(path.exists());
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let contents = fs::read_to_string(path).unwrap();
    assert!(contents.ends_with('\n'));
    assert_eq!(contents.lines().count(), 1);
    assert!(serde_json::from_str::<serde_json::Value>(contents.trim_end()).is_ok());
}

#[test]
fn audit_open_rejects_directory_symlink_special_and_incomplete_destinations() {
    use std::os::unix::fs::{PermissionsExt, symlink};

    let directory = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
    let target = directory.path().join("target.jsonl");
    fs::write(&target, b"{}\n").unwrap();
    let symlink_path = directory.path().join("symlink.jsonl");
    symlink(&target, &symlink_path).unwrap();
    let incomplete = directory.path().join("incomplete.jsonl");
    fs::write(&incomplete, b"{\"complete\":false}").unwrap();
    fs::set_permissions(&incomplete, fs::Permissions::from_mode(0o600)).unwrap();
    let missing_parent = directory.path().join("missing").join("audit.jsonl");

    for path in [
        directory.path(),
        symlink_path.as_path(),
        incomplete.as_path(),
        missing_parent.as_path(),
        std::path::Path::new("/dev/null"),
    ] {
        assert!(AuditLog::open(path).is_err(), "accepted {}", path.display());
    }
}

#[test]
fn audit_open_never_weakens_existing_permissions() {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let directory = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
    let path = directory.path().join("audit.jsonl");
    fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o644)
        .open(&path)
        .unwrap();

    assert!(matches!(
        AuditLog::open(&path),
        Err(AuditError::UnsafeDestination)
    ));
    assert_eq!(
        fs::metadata(path).unwrap().permissions().mode() & 0o777,
        0o644
    );
}

#[test]
fn audit_append_preserves_complete_records_across_restart() {
    let directory = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
    let path = directory.path().join("audit.jsonl");
    fs::write(&path, b"{\"existing\":true}\n").unwrap();
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();

    AuditLog::open(&path).unwrap().record(&denial(2)).unwrap();
    drop(AuditLog::open(&path).unwrap());

    let contents = fs::read_to_string(path).unwrap();
    let lines = contents.lines().collect::<Vec<_>>();
    assert_eq!(lines.len(), 2);
    assert_eq!(lines[0], r#"{"existing":true}"#);
    assert!(serde_json::from_str::<serde_json::Value>(lines[1]).is_ok());
}

#[test]
fn concurrent_audit_writers_produce_individually_parseable_jsonl() {
    let directory = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
    let path = directory.path().join("audit.jsonl");
    let log = Arc::new(AuditLog::open(&path).unwrap());
    let barrier = Arc::new(Barrier::new(17));
    let mut writers = Vec::new();

    for worker in 0_u8..16 {
        let log = Arc::clone(&log);
        let barrier = Arc::clone(&barrier);
        writers.push(thread::spawn(move || {
            barrier.wait();
            for offset in 0_u8..16 {
                log.record(&denial(worker.wrapping_mul(16).wrapping_add(offset)))
                    .unwrap();
            }
        }));
    }
    barrier.wait();
    for writer in writers {
        writer.join().unwrap();
    }

    let contents = fs::read_to_string(path).unwrap();
    assert!(contents.ends_with('\n'));
    let lines = contents.lines().collect::<Vec<_>>();
    assert_eq!(lines.len(), 256);
    assert!(
        lines
            .iter()
            .all(|line| serde_json::from_str::<serde_json::Value>(line).is_ok())
    );
}

fn lifecycle_limits() -> Limits {
    Limits {
        max_sessions: 2,
        max_sessions_per_user: 1,
        idle_timeout: Duration::from_secs(30),
        absolute_timeout: Duration::from_secs(60),
        session_requests_per_window: 10,
        session_request_window: Duration::from_secs(60),
        authentication_failures_per_window: 20,
        authentication_failure_window: Duration::from_secs(60),
    }
}

#[tokio::test]
async fn admitted_session_has_one_correlated_start_and_end() {
    let directory = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
    let path = directory.path().join("audit.jsonl");
    let audit = Arc::new(AuditLog::open(&path).unwrap());
    let manager = SessionManager::new_with_audit(
        lifecycle_limits(),
        TargetAllowlist::new(vec![Target::Pty(PtyTarget {
            name: "quick-exit".into(),
            executable: "/usr/bin/true".into(),
            argv: Vec::new(),
            read_only: false,
        })])
        .unwrap(),
        Arc::clone(&audit),
    );
    let identity = Identity::new("alice").unwrap();
    let remote: SocketAddr = "127.0.0.1:45555".parse().unwrap();

    let mut session = manager
        .start_with_remote(
            identity,
            "quick-exit",
            Resize::new(80, 24).unwrap(),
            Some(remote),
        )
        .await
        .unwrap();
    let closed = session.wait_closed().await.unwrap();
    assert_eq!(closed.reason, SessionCloseReason::ChildExited);

    let values = audit_values(&path);
    assert_eq!(values.len(), 2);
    assert_eq!(values[0]["event_type"], "session-started");
    assert_eq!(values[1]["event_type"], "session-ended");
    assert_eq!(values[0]["session_id"], values[1]["session_id"]);
    assert_eq!(values[0]["identity"], "alice");
    assert_eq!(values[0]["target"], "quick-exit");
    assert_eq!(values[0]["remote_address"], remote.to_string());
    assert_eq!(values[0]["started_at"], values[1]["started_at"]);
    assert_eq!(values[1]["close_reason"], "child-exited");
}

#[tokio::test]
async fn spawn_failure_has_denial_without_orphaned_start() {
    let directory = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
    let path = directory.path().join("audit.jsonl");
    let manager = SessionManager::new_with_audit(
        lifecycle_limits(),
        TargetAllowlist::new(vec![Target::Pty(PtyTarget {
            name: "unavailable".into(),
            executable: "/definitely-not-a-real-audit-fixture".into(),
            argv: Vec::new(),
            read_only: false,
        })])
        .unwrap(),
        Arc::new(AuditLog::open(&path).unwrap()),
    );

    assert!(matches!(
        manager
            .start_with_remote(
                Identity::new("alice").unwrap(),
                "unavailable",
                Resize::new(80, 24).unwrap(),
                Some("127.0.0.1:46666".parse().unwrap()),
            )
            .await,
        Err(SessionError::SpawnUnavailable)
    ));

    let values = audit_values(&path);
    assert_eq!(values.len(), 1);
    assert_eq!(values[0]["event_type"], "access-denied");
    assert_eq!(values[0]["category"], "target");
    assert_eq!(values[0]["reason"], "session-unavailable");
    assert!(
        values
            .iter()
            .all(|value| value["event_type"] != "session-started")
    );
}
