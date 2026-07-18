use std::{
    net::SocketAddr,
    time::{Duration, SystemTime},
};

use ttygated::{
    audit::{AuditEvent, AuditTimestamp, CorrelationId, DenialCategory, DenialReason, SessionId},
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
