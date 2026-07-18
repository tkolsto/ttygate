use std::{net::SocketAddr, sync::Arc, time::Duration};

use axum::extract::ws::{CloseFrame, Message, WebSocket};
use futures_util::{SinkExt, StreamExt};
use serde::Deserialize;
use tokio::{
    sync::{mpsc, watch},
    task::JoinHandle,
};

use crate::{
    audit::{AuditEvent, AuditLog, AuditTimestamp, CorrelationId, DenialCategory, DenialReason},
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
const SOCKET_CLOSE_TIMEOUT: Duration = Duration::from_millis(200);

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
        | SessionError::ReservationUnavailable
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
        | SessionError::AuditUnavailable
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
        SessionCloseReason::TransportDropped => {
            vec![ServerControl::Close(CloseReason::TransportError)]
        }
        SessionCloseReason::HandleDropped => {
            vec![ServerControl::Close(CloseReason::TransportError)]
        }
        SessionCloseReason::SupervisorUnwind => vec![
            error_control(
                "session-unavailable",
                "The terminal session is unavailable.",
            ),
            ServerControl::Close(CloseReason::InternalError),
        ],
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
    audit: Arc<AuditLog>,
    remote_address: Option<SocketAddr>,
) {
    let handshake_deadline = tokio::time::Instant::now() + HANDSHAKE_DEADLINE;
    let message = loop {
        match tokio::time::timeout_at(handshake_deadline, socket.recv()).await {
            Ok(Some(Ok(Message::Ping(_) | Message::Pong(_)))) => {}
            Ok(Some(Err(error))) if is_message_too_large(&error) => {
                send_failure(&mut socket, protocol_failure(ProtocolError::BinaryTooLarge)).await;
                return;
            }
            Ok(Some(Ok(Message::Close(_)))) | Ok(Some(Err(_))) | Ok(None) => {
                return;
            }
            Ok(Some(Ok(message))) => break message,
            Err(_) => {
                deny_ticket(
                    &mut socket,
                    &audit,
                    &identity,
                    remote_address,
                    TicketError::Malformed,
                )
                .await;
                return;
            }
        }
    };
    let ticket = match parse_handshake(&message) {
        Ok(ticket) => ticket,
        Err(HandshakeError::TooLarge) => {
            if record_ticket_denial(&audit, &identity, remote_address, TicketError::Malformed)
                .is_err()
            {
                send_failure(
                    &mut socket,
                    safe_session_error(SessionError::AuditUnavailable),
                )
                .await;
                return;
            }
            send_failure(
                &mut socket,
                protocol_failure(ProtocolError::ControlTooLarge),
            )
            .await;
            return;
        }
        Err(_) => {
            deny_ticket(
                &mut socket,
                &audit,
                &identity,
                remote_address,
                TicketError::Malformed,
            )
            .await;
            return;
        }
    };
    let grant = match tickets.redeem(&ticket, &identity) {
        Ok(grant) => grant,
        Err(error) => {
            deny_ticket(&mut socket, &audit, &identity, remote_address, error).await;
            return;
        }
    };
    let (target, reservation) = grant.into_parts();
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
    let session = match sessions
        .start_reserved_with_remote(reservation, identity, target.name(), size, remote_address)
        .await
    {
        Ok(session) => session,
        Err(error) => {
            send_failure(&mut socket, safe_session_error(error)).await;
            return;
        }
    };

    bridge(socket, session).await;
}

fn record_ticket_denial(
    audit: &AuditLog,
    identity: &Identity,
    remote_address: Option<SocketAddr>,
    error: TicketError,
) -> Result<(), ()> {
    let reason = match error {
        TicketError::Malformed => DenialReason::TicketMalformed,
        TicketError::Unknown => DenialReason::TicketUnknown,
        TicketError::Expired => DenialReason::TicketExpired,
        TicketError::WrongIdentity => DenialReason::TicketWrongIdentity,
        TicketError::AtCapacity => DenialReason::TicketCapacity,
        TicketError::Generation => DenialReason::TicketGeneration,
    };
    let correlation_id = CorrelationId::generate().map_err(|_| ())?;
    let occurred_at = AuditTimestamp::now().map_err(|_| ())?;
    audit
        .record(&AuditEvent::access_denied(
            correlation_id,
            DenialCategory::Ticket,
            reason,
            Some(identity),
            None,
            remote_address,
            occurred_at,
        ))
        .map_err(|_| ())
}

async fn deny_ticket(
    socket: &mut WebSocket,
    audit: &AuditLog,
    identity: &Identity,
    remote_address: Option<SocketAddr>,
    error: TicketError,
) {
    let failure = if record_ticket_denial(audit, identity, remote_address, error).is_ok() {
        safe_ticket_error(error)
    } else {
        safe_session_error(SessionError::AuditUnavailable)
    };
    send_failure(socket, failure).await;
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
    BackpressuredTerminal,
    Failure(BridgeFailure),
    Transport,
}

enum Inbound {
    Message(Message),
    Failure(BridgeFailure),
}

#[derive(Debug, PartialEq, Eq)]
enum SendCompletion<S, C> {
    Sent(S),
    Completed(C),
}

async fn race_send_with_completion<S, C>(
    send: impl std::future::Future<Output = S>,
    completion: impl std::future::Future<Output = C>,
) -> SendCompletion<S, C> {
    tokio::select! {
        biased;
        sent = send => SendCompletion::Sent(sent),
        completed = completion => SendCompletion::Completed(completed),
    }
}

async fn bridge(socket: WebSocket, mut session: Session) {
    let (sink, stream) = socket.split();
    let (inbound_tx, mut inbound_rx) = mpsc::channel(BRIDGE_CHANNEL_CAPACITY);
    let (outbound_tx, outbound_rx) = mpsc::channel(BRIDGE_CHANNEL_CAPACITY);
    let (cancel_tx, mut cancel_rx) = watch::channel(false);
    let (stop_input_tx, stop_input_rx) = watch::channel(false);

    let reader = tokio::spawn(read_socket(
        stream,
        inbound_tx,
        outbound_tx.clone(),
        cancel_tx.clone(),
        cancel_rx.clone(),
        stop_input_rx,
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
                let inbound = match inbound {
                    Inbound::Message(message) => message,
                    Inbound::Failure(failure) => {
                        break Termination::Failure(failure);
                    }
                };
                match handle_client_message(
                    inbound,
                    &mut session,
                    &mut cancel_rx,
                    &stop_input_tx,
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
                        match race_send_with_completion(
                            send_bounded(
                                &outbound_tx,
                                frame,
                                &mut cancel_rx,
                            ),
                            session.wait_closed(),
                        )
                        .await
                        {
                            SendCompletion::Sent(Ok(())) => {}
                            SendCompletion::Sent(Err(())) => {
                                break Termination::Transport;
                            }
                            SendCompletion::Completed(Ok(_)) => {
                                break Termination::BackpressuredTerminal;
                            }
                            SendCompletion::Completed(Err(error)) => {
                                break Termination::Failure(
                                    safe_session_error(error),
                                );
                            }
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
    stop_input_tx.send_replace(true);

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
    stop_input: &watch::Sender<bool>,
) -> Result<Option<SessionClosed>, BridgeFailure> {
    match message {
        Message::Binary(bytes) => {
            let frame = protocol::decode_client_binary(&bytes).map_err(protocol_failure)?;
            let ClientFrame::TerminalInput(bytes) = frame else {
                unreachable!("binary decoder only produces terminal input");
            };
            let result = cancellable_session(session.write(bytes), cancel).await;
            resolve_session_operation(result, session, cancel).await
        }
        Message::Text(text) => {
            let control =
                protocol::decode_client_control(text.as_bytes()).map_err(protocol_failure)?;
            match control {
                ClientControl::Resize(size) => {
                    let result = cancellable_session(session.resize(size), cancel).await;
                    resolve_session_operation(result, session, cancel).await
                }
                ClientControl::Close => {
                    stop_input_before(stop_input, cancellable_session(session.close(), cancel))
                        .await
                        .map(Some)
                        .map_err(safe_session_error)
                }
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

async fn resolve_session_operation<T>(
    result: Result<T, SessionError>,
    session: &mut Session,
    cancel: &watch::Receiver<bool>,
) -> Result<Option<SessionClosed>, BridgeFailure> {
    match result {
        Ok(_) => Ok(None),
        Err(SessionError::Closed) if !*cancel.borrow() => {
            terminal_operation_result(session.wait_closed().await)
        }
        Err(error) => Err(safe_session_error(error)),
    }
}

fn terminal_operation_result(
    result: Result<SessionClosed, SessionError>,
) -> Result<Option<SessionClosed>, BridgeFailure> {
    result.map(Some).map_err(safe_session_error)
}

async fn stop_input_before<T>(
    stop_input: &watch::Sender<bool>,
    operation: impl std::future::Future<Output = T>,
) -> T {
    stop_input.send_replace(true);
    operation.await
}

async fn await_or_cancel<T>(
    operation: impl std::future::Future<Output = T>,
    cancel: &mut watch::Receiver<bool>,
) -> Option<T> {
    tokio::select! {
        biased;
        _ = cancelled(cancel) => None,
        result = operation => Some(result),
    }
}

async fn close_or_cancel<T>(
    operation: impl std::future::Future<Output = T>,
    cancel: &mut watch::Receiver<bool>,
) -> Option<T> {
    let bounded = tokio::time::timeout(SOCKET_CLOSE_TIMEOUT, operation);
    tokio::pin!(bounded);
    if *cancel.borrow() {
        return bounded.await.ok();
    }
    tokio::select! {
        biased;
        _ = cancelled(cancel) => None,
        result = &mut bounded => result.ok(),
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
    inbound: mpsc::Sender<Inbound>,
    outbound: mpsc::Sender<Message>,
    cancel_tx: watch::Sender<bool>,
    mut cancel: watch::Receiver<bool>,
    mut stop_input: watch::Receiver<bool>,
) {
    loop {
        let message = tokio::select! {
            biased;
            _ = cancelled(&mut cancel) => break,
            _ = cancelled(&mut stop_input) => break,
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
            Some(Err(error)) if is_message_too_large(&error) => {
                let _ = send_bounded(
                    &inbound,
                    Inbound::Failure(protocol_failure(ProtocolError::BinaryTooLarge)),
                    &mut cancel,
                )
                .await;
                break;
            }
            Some(Ok(Message::Close(_))) | Some(Err(_)) | None => {
                cancel_tx.send_replace(true);
                break;
            }
            Some(Ok(message @ (Message::Text(_) | Message::Binary(_)))) => {
                if send_bounded(&inbound, Inbound::Message(message), &mut cancel)
                    .await
                    .is_err()
                {
                    break;
                }
            }
        }
    }
}

fn is_message_too_large(error: &axum::Error) -> bool {
    std::error::Error::source(error)
        .and_then(|error| error.downcast_ref::<tungstenite::Error>())
        .is_some_and(|error| {
            matches!(
                error,
                tungstenite::Error::Capacity(
                    tungstenite::error::CapacityError::MessageTooLong { .. }
                )
            )
        })
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
        let sent = await_or_cancel(sink.send(message), &mut cancel)
            .await
            .is_some_and(|result| result.is_ok());
        if !sent {
            cancel_tx.send_replace(true);
            break;
        }
        if is_close {
            return;
        }
    }
    let _ = close_or_cancel(sink.close(), &mut cancel).await;
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
        Termination::BackpressuredTerminal => {
            cancel_tx.send_replace(true);
            join_task(reader).await;
            join_task(writer).await;
            return;
        }
        Termination::Transport => {
            let _ = session.transport_dropped().await;
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
        BRIDGE_CHANNEL_CAPACITY, HANDSHAKE_MAX_BYTES, HandshakeError, SendCompletion,
        close_or_cancel, parse_handshake, race_send_with_completion, resolve_session_operation,
        safe_session_error, safe_ticket_error, send_bounded, stop_input_before, terminal_controls,
        terminal_operation_result,
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
            SessionError::ReservationUnavailable,
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
            SessionError::ReservationUnavailable,
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

    #[tokio::test]
    async fn client_close_stops_input_before_awaiting_session_teardown() {
        let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
        let result = stop_input_before(&stop_tx, async move {
            assert!(*stop_rx.borrow());
            7
        })
        .await;
        assert_eq!(result, 7);
    }

    #[tokio::test]
    async fn blocked_socket_close_is_directly_cancellation_selectable() {
        let (cancel_tx, cancel_rx) = tokio::sync::watch::channel(false);
        let blocked = tokio::spawn(async move {
            let mut cancel_rx = cancel_rx;
            close_or_cancel(std::future::pending::<()>(), &mut cancel_rx).await
        });
        tokio::task::yield_now().await;
        assert!(!blocked.is_finished());
        cancel_tx.send_replace(true);
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), blocked)
                .await
                .unwrap()
                .unwrap(),
            None
        );
    }

    #[tokio::test]
    async fn queued_transport_close_gets_one_bounded_flush_after_cancellation() {
        let (_cancel_tx, mut cancel_rx) = tokio::sync::watch::channel(true);
        assert_eq!(
            close_or_cancel(std::future::ready(23), &mut cancel_rx).await,
            Some(23)
        );
    }

    #[tokio::test]
    async fn session_completion_interrupts_a_backpressured_output_send() {
        let outcome = race_send_with_completion(
            std::future::pending::<Result<(), ()>>(),
            std::future::ready(17_u8),
        )
        .await;
        assert_eq!(outcome, SendCompletion::Completed(17));
    }

    #[test]
    fn late_client_operation_preserves_the_actual_terminal_snapshot() {
        let closed = SessionClosed {
            state: SessionState::Closed,
            reason: SessionCloseReason::ChildExited,
            outcome: Some(ChildOutcome::Code(0)),
        };
        assert_eq!(terminal_operation_result(Ok(closed)), Ok(Some(closed)));
    }

    #[tokio::test]
    async fn closed_client_operation_resolves_the_real_session_terminal_state() {
        let target = crate::config::Target::Pty(crate::config::PtyTarget {
            name: "immediate-exit".into(),
            executable: "/usr/bin/true".into(),
            argv: Vec::new(),
            read_only: false,
        });
        let manager = crate::session::SessionManager::new(
            crate::config::Limits {
                max_sessions: 1,
                max_sessions_per_user: 1,
                idle_timeout: Duration::from_secs(2),
                absolute_timeout: Duration::from_secs(2),
                session_requests_per_window: 10,
                session_request_window: Duration::from_secs(60),
                authentication_failures_per_window: 20,
                authentication_failure_window: Duration::from_secs(60),
            },
            crate::config::TargetAllowlist::new(vec![target]).unwrap(),
        );
        let mut session = manager
            .start(
                crate::ticket::Identity::new("review-test").unwrap(),
                "immediate-exit",
                crate::protocol::Resize::new(80, 24).unwrap(),
            )
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(2), async {
            while session.state() != SessionState::Closed {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let (_cancel_tx, cancel_rx) = tokio::sync::watch::channel(false);
        let resolved =
            resolve_session_operation::<()>(Err(SessionError::Closed), &mut session, &cancel_rx)
                .await
                .unwrap()
                .unwrap();
        assert_eq!(resolved.reason, SessionCloseReason::ChildExited);
        assert_eq!(resolved.outcome, Some(ChildOutcome::Code(0)));
    }
}
