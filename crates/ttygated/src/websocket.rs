use std::{sync::Arc, time::Duration};

use axum::extract::ws::{CloseFrame, Message, WebSocket};
use futures_util::{SinkExt, StreamExt};
use serde::Deserialize;
use tokio::{
    sync::{mpsc, watch},
    task::JoinHandle,
};

use crate::{
    config::Target,
    protocol::{
        self, ClientControl, ClientFrame, CloseReason, ProtocolError, ProtocolErrorMessage, Resize,
        ServerControl, ServerFrame,
    },
    session::{Session, SessionCloseReason, SessionClosed, SessionError, SessionManager},
    ticket::{Identity, TicketError, TicketStore},
};

pub const HANDSHAKE_MAX_BYTES: usize = 256;
const HANDSHAKE_DEADLINE: Duration = Duration::from_secs(1);
const INITIAL_COLS: u16 = 80;
const INITIAL_ROWS: u16 = 24;
pub const BRIDGE_CHANNEL_CAPACITY: usize = 4;
const TASK_JOIN_TIMEOUT: Duration = Duration::from_secs(1);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HandshakeError {
    WrongType,
    Empty,
    TooLarge,
    Malformed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BridgeFailure {
    error: ServerControl,
    close_reason: CloseReason,
    websocket_code: u16,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TicketEnvelope {
    ticket: String,
}

fn parse_handshake(message: &Message) -> Result<String, HandshakeError> {
    let Message::Text(text) = message else {
        return Err(HandshakeError::WrongType);
    };
    let bytes = text.as_bytes();
    if bytes.is_empty() {
        return Err(HandshakeError::Empty);
    }
    if bytes.len() > HANDSHAKE_MAX_BYTES {
        return Err(HandshakeError::TooLarge);
    }
    let envelope: TicketEnvelope =
        serde_json::from_slice(bytes).map_err(|_| HandshakeError::Malformed)?;
    if envelope.ticket.is_empty() {
        return Err(HandshakeError::Malformed);
    }
    Ok(envelope.ticket)
}

fn error_control(code: &'static str, message: &'static str) -> ServerControl {
    ServerControl::Error(
        ProtocolErrorMessage::new(code, message)
            .expect("bridge error constants satisfy the protocol"),
    )
}

fn safe_ticket_error(_error: TicketError) -> BridgeFailure {
    BridgeFailure {
        error: error_control("authorization-denied", "Session authorization was denied."),
        close_reason: CloseReason::Policy,
        websocket_code: 1008,
    }
}

fn safe_session_error(error: SessionError) -> BridgeFailure {
    match error {
        SessionError::GlobalLimit
        | SessionError::IdentityLimit
        | SessionError::TargetUnavailable
        | SessionError::ManagerClosed
        | SessionError::ReadOnly => BridgeFailure {
            error: error_control("session-denied", "The terminal session is not available."),
            close_reason: CloseReason::Policy,
            websocket_code: 1008,
        },
        SessionError::InputTooLarge | SessionError::InvalidResize => BridgeFailure {
            error: error_control("protocol-error", "The terminal protocol is invalid."),
            close_reason: CloseReason::ProtocolError,
            websocket_code: 1008,
        },
        SessionError::SpawnUnavailable
        | SessionError::BackendUnavailable
        | SessionError::Closed
        | SessionError::InvalidTransition => BridgeFailure {
            error: error_control(
                "session-unavailable",
                "The terminal session is unavailable.",
            ),
            close_reason: CloseReason::InternalError,
            websocket_code: 1011,
        },
    }
}

fn terminal_controls(closed: SessionClosed) -> Vec<ServerControl> {
    match closed.reason {
        SessionCloseReason::ChildExited => {
            let mut controls = Vec::with_capacity(2);
            if let Some(outcome) = closed.outcome {
                controls.push(ServerControl::ExitStatus(outcome.as_protocol()));
            }
            controls.push(ServerControl::Close(CloseReason::Exited));
            controls
        }
        SessionCloseReason::Explicit => {
            vec![ServerControl::Close(CloseReason::ClientRequest)]
        }
        SessionCloseReason::HandleDropped => {
            vec![ServerControl::Close(CloseReason::TransportError)]
        }
        SessionCloseReason::ManagerShutdown => {
            vec![ServerControl::Close(CloseReason::Policy)]
        }
        SessionCloseReason::Timeout(_) => {
            vec![ServerControl::Close(CloseReason::Timeout)]
        }
        SessionCloseReason::BackendFailure => vec![
            error_control(
                "session-unavailable",
                "The terminal session is unavailable.",
            ),
            ServerControl::Close(CloseReason::InternalError),
        ],
    }
}

pub async fn accept_upgrade(
    mut socket: WebSocket,
    identity: Identity,
    tickets: Arc<TicketStore>,
    sessions: Arc<SessionManager>,
) {
    let message = match tokio::time::timeout(HANDSHAKE_DEADLINE, socket.recv()).await {
        Ok(Some(Ok(message))) => message,
        Ok(Some(Err(_))) | Ok(None) | Err(_) => {
            send_failure(&mut socket, safe_ticket_error(TicketError::Malformed)).await;
            return;
        }
    };
    let ticket = match parse_handshake(&message) {
        Ok(ticket) => ticket,
        Err(HandshakeError::TooLarge) => {
            send_failure(
                &mut socket,
                protocol_failure(ProtocolError::ControlTooLarge),
            )
            .await;
            return;
        }
        Err(_) => {
            send_failure(&mut socket, safe_ticket_error(TicketError::Malformed)).await;
            return;
        }
    };
    let target = match tickets.redeem(&ticket, &identity) {
        Ok(target) => target,
        Err(error) => {
            send_failure(&mut socket, safe_ticket_error(error)).await;
            return;
        }
    };
    if !matches!(target, Target::Pty(_)) {
        send_failure(
            &mut socket,
            safe_session_error(SessionError::TargetUnavailable),
        )
        .await;
        return;
    }
    let size =
        Resize::new(INITIAL_COLS, INITIAL_ROWS).expect("the fixed initial terminal size is valid");
    let session = match sessions.start(identity, target.name(), size).await {
        Ok(session) => session,
        Err(error) => {
            send_failure(&mut socket, safe_session_error(error)).await;
            return;
        }
    };

    bridge(socket, session).await;
}

async fn send_control(socket: &mut WebSocket, control: &ServerControl) -> Result<(), ()> {
    let encoded = protocol::encode_server_control(control).map_err(|_| ())?;
    socket
        .send(Message::Text(encoded.into()))
        .await
        .map_err(|_| ())
}

async fn send_failure(socket: &mut WebSocket, failure: BridgeFailure) {
    let _ = send_control(socket, &failure.error).await;
    let _ = send_control(socket, &ServerControl::Close(failure.close_reason)).await;
    let _ = socket
        .send(Message::Close(Some(CloseFrame {
            code: failure.websocket_code,
            reason: String::new().into(),
        })))
        .await;
}

enum Termination {
    Terminal(SessionClosed),
    Failure(BridgeFailure),
    Transport,
}

async fn bridge(socket: WebSocket, mut session: Session) {
    let (sink, stream) = socket.split();
    let (inbound_tx, mut inbound_rx) = mpsc::channel(BRIDGE_CHANNEL_CAPACITY);
    let (outbound_tx, outbound_rx) = mpsc::channel(BRIDGE_CHANNEL_CAPACITY);
    let (cancel_tx, mut cancel_rx) = watch::channel(false);

    let reader = tokio::spawn(read_socket(
        stream,
        inbound_tx,
        outbound_tx.clone(),
        cancel_tx.clone(),
        cancel_rx.clone(),
    ));
    let writer = tokio::spawn(write_socket(
        sink,
        outbound_rx,
        cancel_tx.clone(),
        cancel_rx.clone(),
    ));

    let termination = loop {
        tokio::select! {
            biased;
            _ = cancelled(&mut cancel_rx) => break Termination::Transport,
            inbound = inbound_rx.recv() => {
                let Some(inbound) = inbound else {
                    break Termination::Transport;
                };
                match handle_client_message(
                    inbound,
                    &mut session,
                    &mut cancel_rx,
                ).await {
                    Ok(Some(closed)) => break Termination::Terminal(closed),
                    Ok(None) => {}
                    Err(failure) => break Termination::Failure(failure),
                }
            }
            output = session.read() => {
                match output {
                    Ok(bytes) => {
                        let frame = match protocol::decode_server_binary(&bytes) {
                            Ok(ServerFrame::TerminalOutput(bytes)) => {
                                Message::Binary(bytes.into())
                            }
                            Ok(ServerFrame::Control(_)) => unreachable!(
                                "binary decoder only produces terminal output"
                            ),
                            Err(_) => {
                                break Termination::Failure(internal_failure());
                            }
                        };
                        if send_bounded(&outbound_tx, frame, &mut cancel_rx)
                            .await
                            .is_err()
                        {
                            break Termination::Transport;
                        }
                    }
                    Err(SessionError::Closed) => {
                        match session.wait_closed().await {
                            Ok(closed) => break Termination::Terminal(closed),
                            Err(error) => {
                                break Termination::Failure(safe_session_error(error));
                            }
                        }
                    }
                    Err(error) => {
                        break Termination::Failure(safe_session_error(error));
                    }
                }
            }
        }
    };

    finish_bridge(
        termination,
        &mut session,
        outbound_tx,
        cancel_tx,
        cancel_rx,
        reader,
        writer,
    )
    .await;
}

async fn handle_client_message(
    message: Message,
    session: &mut Session,
    cancel: &mut watch::Receiver<bool>,
) -> Result<Option<SessionClosed>, BridgeFailure> {
    match message {
        Message::Binary(bytes) => {
            let frame = protocol::decode_client_binary(&bytes).map_err(protocol_failure)?;
            let ClientFrame::TerminalInput(bytes) = frame else {
                unreachable!("binary decoder only produces terminal input");
            };
            cancellable_session(session.write(bytes), cancel)
                .await
                .map_err(safe_session_error)?;
            Ok(None)
        }
        Message::Text(text) => {
            let control =
                protocol::decode_client_control(text.as_bytes()).map_err(protocol_failure)?;
            match control {
                ClientControl::Resize(size) => {
                    cancellable_session(session.resize(size), cancel)
                        .await
                        .map_err(safe_session_error)?;
                    Ok(None)
                }
                ClientControl::Close => cancellable_session(session.close(), cancel)
                    .await
                    .map(Some)
                    .map_err(safe_session_error),
            }
        }
        Message::Close(_) => Err(transport_failure()),
        Message::Ping(_) | Message::Pong(_) => Ok(None),
    }
}

async fn cancellable_session<T>(
    operation: impl std::future::Future<Output = Result<T, SessionError>>,
    cancel: &mut watch::Receiver<bool>,
) -> Result<T, SessionError> {
    tokio::select! {
        biased;
        _ = cancelled(cancel) => Err(SessionError::Closed),
        result = operation => result,
    }
}

fn protocol_failure(error: ProtocolError) -> BridgeFailure {
    let websocket_code = match error {
        ProtocolError::BinaryTooLarge | ProtocolError::ControlTooLarge => 1009,
        _ => 1008,
    };
    BridgeFailure {
        error: error_control("protocol-error", "The terminal protocol is invalid."),
        close_reason: CloseReason::ProtocolError,
        websocket_code,
    }
}

fn internal_failure() -> BridgeFailure {
    BridgeFailure {
        error: error_control(
            "session-unavailable",
            "The terminal session is unavailable.",
        ),
        close_reason: CloseReason::InternalError,
        websocket_code: 1011,
    }
}

fn transport_failure() -> BridgeFailure {
    BridgeFailure {
        error: error_control(
            "session-unavailable",
            "The terminal session is unavailable.",
        ),
        close_reason: CloseReason::TransportError,
        websocket_code: 1001,
    }
}

async fn read_socket(
    mut stream: futures_util::stream::SplitStream<WebSocket>,
    inbound: mpsc::Sender<Message>,
    outbound: mpsc::Sender<Message>,
    cancel_tx: watch::Sender<bool>,
    mut cancel: watch::Receiver<bool>,
) {
    loop {
        let message = tokio::select! {
            biased;
            _ = cancelled(&mut cancel) => break,
            message = stream.next() => message,
        };
        match message {
            Some(Ok(Message::Ping(payload))) => {
                if send_bounded(&outbound, Message::Pong(payload), &mut cancel)
                    .await
                    .is_err()
                {
                    break;
                }
            }
            Some(Ok(Message::Pong(_))) => {}
            Some(Ok(Message::Close(_))) | Some(Err(_)) | None => {
                cancel_tx.send_replace(true);
                break;
            }
            Some(Ok(message @ (Message::Text(_) | Message::Binary(_)))) => {
                if send_bounded(&inbound, message, &mut cancel).await.is_err() {
                    break;
                }
            }
        }
    }
}

async fn write_socket(
    mut sink: futures_util::stream::SplitSink<WebSocket, Message>,
    mut outbound: mpsc::Receiver<Message>,
    cancel_tx: watch::Sender<bool>,
    mut cancel: watch::Receiver<bool>,
) {
    loop {
        let message = tokio::select! {
            biased;
            _ = cancelled(&mut cancel) => break,
            message = outbound.recv() => match message {
                Some(message) => message,
                None => break,
            },
        };
        let is_close = matches!(message, Message::Close(_));
        let sent = tokio::select! {
            biased;
            _ = cancelled(&mut cancel) => false,
            result = sink.send(message) => result.is_ok(),
        };
        if !sent {
            cancel_tx.send_replace(true);
            break;
        }
        if is_close {
            return;
        }
    }
    let _ = sink.close().await;
}

async fn send_bounded<T>(
    sender: &mpsc::Sender<T>,
    value: T,
    cancel: &mut watch::Receiver<bool>,
) -> Result<(), ()> {
    tokio::select! {
        biased;
        _ = cancelled(cancel) => Err(()),
        result = sender.send(value) => result.map_err(|_| ()),
    }
}

async fn finish_bridge(
    termination: Termination,
    session: &mut Session,
    outbound: mpsc::Sender<Message>,
    cancel_tx: watch::Sender<bool>,
    mut cancel_rx: watch::Receiver<bool>,
    reader: JoinHandle<()>,
    mut writer: JoinHandle<()>,
) {
    let (controls, websocket_code) = match termination {
        Termination::Terminal(closed) => (terminal_controls(closed), 1000),
        Termination::Failure(failure) => {
            let _ = session.close().await;
            (
                vec![failure.error, ServerControl::Close(failure.close_reason)],
                failure.websocket_code,
            )
        }
        Termination::Transport => {
            let _ = session.close().await;
            cancel_tx.send_replace(true);
            join_task(reader).await;
            join_task(writer).await;
            return;
        }
    };

    for control in controls {
        let Ok(encoded) = protocol::encode_server_control(&control) else {
            break;
        };
        if send_bounded(&outbound, Message::Text(encoded.into()), &mut cancel_rx)
            .await
            .is_err()
        {
            break;
        }
    }
    let _ = send_bounded(
        &outbound,
        Message::Close(Some(CloseFrame {
            code: websocket_code,
            reason: String::new().into(),
        })),
        &mut cancel_rx,
    )
    .await;
    drop(outbound);

    let writer_finished = tokio::time::timeout(TASK_JOIN_TIMEOUT, &mut writer)
        .await
        .is_ok();
    if !writer_finished {
        cancel_tx.send_replace(true);
    }
    cancel_tx.send_replace(true);
    join_task(reader).await;
    if !writer_finished {
        join_task(writer).await;
    }
}

async fn join_task(mut task: JoinHandle<()>) {
    if tokio::time::timeout(TASK_JOIN_TIMEOUT, &mut task)
        .await
        .is_err()
    {
        task.abort();
        let _ = task.await;
    }
}

async fn cancelled(receiver: &mut watch::Receiver<bool>) {
    while !*receiver.borrow_and_update() {
        if receiver.changed().await.is_err() {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use axum::extract::ws::Message;

    use crate::{
        protocol::{CloseReason, ExitStatus, ServerControl},
        session::{
            ChildOutcome, SessionCloseReason, SessionClosed, SessionError, SessionState,
            TimeoutKind,
        },
        ticket::TicketError,
    };

    use super::{
        BRIDGE_CHANNEL_CAPACITY, HANDSHAKE_MAX_BYTES, HandshakeError, parse_handshake,
        safe_session_error, safe_ticket_error, send_bounded, terminal_controls,
    };

    #[test]
    fn websocket_dependency_surface_compiles() {
        fn assert_stream_and_sink<T>()
        where
            T: futures_util::Stream + futures_util::Sink<axum::extract::ws::Message>,
        {
        }

        assert_stream_and_sink::<axum::extract::ws::WebSocket>();
    }

    #[test]
    fn handshake_accepts_only_the_closed_ticket_schema() {
        let ticket = "A".repeat(43);
        assert_eq!(
            parse_handshake(&Message::Text(format!(r#"{{"ticket":"{ticket}"}}"#).into())),
            Ok(ticket)
        );

        for invalid in [
            r#"{}"#,
            r#"{"ticket":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","extra":true}"#,
            r#"{"ticket":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","ticket":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"}"#,
            r#"{"ticket":1}"#,
            r#"[]"#,
            r#"not json"#,
            r#"{"ticket":""}"#,
        ] {
            assert_eq!(
                parse_handshake(&Message::Text(invalid.to_owned().into())),
                Err(HandshakeError::Malformed),
                "{invalid}"
            );
        }
    }

    #[test]
    fn handshake_rejects_wrong_frame_type_empty_and_oversize_before_parsing() {
        assert_eq!(
            parse_handshake(&Message::Binary(Vec::new().into())),
            Err(HandshakeError::WrongType)
        );
        assert_eq!(
            parse_handshake(&Message::Text(String::new().into())),
            Err(HandshakeError::Empty)
        );
        let oversized = "x".repeat(HANDSHAKE_MAX_BYTES + 1);
        assert_eq!(
            parse_handshake(&Message::Text(oversized.into())),
            Err(HandshakeError::TooLarge)
        );
    }

    #[test]
    fn ticket_error_mapping_is_stable_and_non_reflecting() {
        for error in [
            TicketError::Malformed,
            TicketError::Unknown,
            TicketError::Expired,
            TicketError::WrongIdentity,
            TicketError::AtCapacity,
            TicketError::Generation,
        ] {
            let failure = safe_ticket_error(error);
            let rendered = format!("{failure:?}");
            assert_eq!(failure.websocket_code, 1008);
            assert_eq!(failure.close_reason, CloseReason::Policy);
            assert!(matches!(
                failure.error,
                ServerControl::Error(ref message)
                    if message.code == "authorization-denied"
                        && message.message == "Session authorization was denied."
            ));
            for sentinel in [
                "ticket-secret",
                "cookie-secret",
                "identity-secret",
                "/private/command",
                "raw backend failure",
            ] {
                assert!(!rendered.contains(sentinel));
            }
        }
    }

    #[test]
    fn session_mapping_covers_every_error_with_curated_controls() {
        let policy = [
            SessionError::GlobalLimit,
            SessionError::IdentityLimit,
            SessionError::TargetUnavailable,
            SessionError::ManagerClosed,
            SessionError::ReadOnly,
        ];
        for error in policy {
            let failure = safe_session_error(error);
            assert_eq!(failure.websocket_code, 1008);
            assert_eq!(failure.close_reason, CloseReason::Policy);
        }

        for error in [SessionError::InputTooLarge, SessionError::InvalidResize] {
            let failure = safe_session_error(error);
            assert_eq!(failure.websocket_code, 1008);
            assert_eq!(failure.close_reason, CloseReason::ProtocolError);
        }

        for error in [
            SessionError::SpawnUnavailable,
            SessionError::BackendUnavailable,
            SessionError::Closed,
            SessionError::InvalidTransition,
        ] {
            let failure = safe_session_error(error);
            assert_eq!(failure.websocket_code, 1011);
            assert_eq!(failure.close_reason, CloseReason::InternalError);
        }

        for error in [
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
        ] {
            let failure = safe_session_error(error);
            let ServerControl::Error(message) = failure.error else {
                panic!("session errors must map to a typed error control");
            };
            assert!(matches!(
                message.code.as_str(),
                "session-denied" | "protocol-error" | "session-unavailable"
            ));
            assert!(!message.message.contains("raw"));
            assert!(!message.message.contains("/private"));
        }
    }

    #[test]
    fn session_mapping_emits_only_permitted_exit_status_then_final_close() {
        let cases = [
            (
                SessionCloseReason::ChildExited,
                Some(ChildOutcome::Code(7)),
                vec![
                    ServerControl::ExitStatus(ExitStatus::Code(7)),
                    ServerControl::Close(CloseReason::Exited),
                ],
            ),
            (
                SessionCloseReason::ChildExited,
                Some(ChildOutcome::Signal(15)),
                vec![
                    ServerControl::ExitStatus(ExitStatus::Signal(15)),
                    ServerControl::Close(CloseReason::Exited),
                ],
            ),
            (
                SessionCloseReason::ChildExited,
                None,
                vec![ServerControl::Close(CloseReason::Exited)],
            ),
            (
                SessionCloseReason::Explicit,
                Some(ChildOutcome::Signal(1)),
                vec![ServerControl::Close(CloseReason::ClientRequest)],
            ),
            (
                SessionCloseReason::HandleDropped,
                None,
                vec![ServerControl::Close(CloseReason::TransportError)],
            ),
            (
                SessionCloseReason::ManagerShutdown,
                None,
                vec![ServerControl::Close(CloseReason::Policy)],
            ),
            (
                SessionCloseReason::Timeout(TimeoutKind::Idle),
                None,
                vec![ServerControl::Close(CloseReason::Timeout)],
            ),
        ];

        for (reason, outcome, expected) in cases {
            assert_eq!(
                terminal_controls(SessionClosed {
                    state: SessionState::Closed,
                    reason,
                    outcome,
                }),
                expected
            );
        }

        let backend = terminal_controls(SessionClosed {
            state: SessionState::Closed,
            reason: SessionCloseReason::BackendFailure,
            outcome: Some(ChildOutcome::Unavailable),
        });
        assert!(
            matches!(backend.first(), Some(ServerControl::Error(message))
            if message.code == "session-unavailable")
        );
        assert_eq!(
            backend.last(),
            Some(&ServerControl::Close(CloseReason::InternalError))
        );
    }

    #[tokio::test]
    async fn bridge_channel_capacity_is_hard_bounded_and_send_is_cancellable() {
        let (sender, mut receiver) = tokio::sync::mpsc::channel(BRIDGE_CHANNEL_CAPACITY);
        for value in 0..BRIDGE_CHANNEL_CAPACITY {
            sender.try_send(value).unwrap();
        }
        assert!(matches!(
            sender.try_send(usize::MAX),
            Err(tokio::sync::mpsc::error::TrySendError::Full(_))
        ));

        let (cancel_tx, cancel_rx) = tokio::sync::watch::channel(false);
        let blocked = tokio::spawn(async move {
            let mut cancel_rx = cancel_rx;
            send_bounded(&sender, usize::MAX, &mut cancel_rx).await
        });
        tokio::task::yield_now().await;
        assert!(!blocked.is_finished());
        cancel_tx.send_replace(true);
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), blocked)
                .await
                .unwrap()
                .unwrap(),
            Err(())
        );
        assert_eq!(receiver.recv().await, Some(0));
    }
}
