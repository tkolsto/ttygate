use std::{net::SocketAddr, time::Duration};

use axum::{
    Router,
    extract::{
        State,
        ws::{Message, WebSocket, WebSocketUpgrade},
    },
    response::IntoResponse,
    routing::get,
};
use futures_util::{SinkExt, StreamExt};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::{mpsc, oneshot},
    task::JoinHandle,
    time::{sleep, timeout},
};
use tokio_tungstenite::{connect_async, tungstenite};

const TIMEOUT: Duration = Duration::from_secs(3);

#[derive(Debug)]
struct Server {
    address: SocketAddr,
    shutdown: oneshot::Sender<()>,
    bridge_stopped: mpsc::Receiver<()>,
    task: JoinHandle<()>,
}

async fn healthz() -> &'static str {
    "ok"
}

async fn upgrade(
    State(stopped): State<mpsc::Sender<()>>,
    ws: WebSocketUpgrade,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| async move {
        bridge(socket).await;
        let _ = stopped.send(()).await;
    })
}

async fn bridge(socket: WebSocket) {
    let (mut ws_out, mut ws_in) = socket.split();
    let (to_session_tx, mut to_session_rx) = mpsc::channel::<Message>(1);
    let (from_session_tx, mut from_session_rx) = mpsc::channel::<Message>(1);

    let input = tokio::spawn(async move {
        while let Some(result) = ws_in.next().await {
            match result {
                Ok(Message::Text(text)) => {
                    if to_session_tx.send(Message::Text(text)).await.is_err() {
                        break;
                    }
                }
                Ok(Message::Binary(bytes)) => {
                    if to_session_tx.send(Message::Binary(bytes)).await.is_err() {
                        break;
                    }
                }
                Ok(Message::Close(_)) | Err(_) => break,
                Ok(Message::Ping(_)) | Ok(Message::Pong(_)) => {}
            }
        }
    });

    let session = tokio::spawn(async move {
        while let Some(message) = to_session_rx.recv().await {
            if from_session_tx.send(message).await.is_err() {
                break;
            }
        }
    });

    let output = tokio::spawn(async move {
        while let Some(message) = from_session_rx.recv().await {
            if ws_out.send(message).await.is_err() {
                break;
            }
        }
        let _ = ws_out.close().await;
    });

    let _ = input.await;
    session.abort();
    output.abort();
    let _ = session.await;
    let _ = output.await;
}

async fn start_server() -> Server {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address = listener.local_addr().expect("local address");
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let (bridge_stopped_tx, bridge_stopped_rx) = mpsc::channel(1);
    let app = Router::new()
        .route("/healthz", get(healthz))
        .route("/ws", get(upgrade))
        .with_state(bridge_stopped_tx);
    let task = tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(async move {
                let _ = shutdown_rx.await;
            })
            .await
            .expect("serve");
    });
    Server {
        address,
        shutdown: shutdown_tx,
        bridge_stopped: bridge_stopped_rx,
        task,
    }
}

async fn assert_http_route(address: SocketAddr) {
    let mut stream = TcpStream::connect(address).await.expect("connect HTTP");
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    stream
        .write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .expect("write HTTP request");
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.expect("read HTTP");
    let response = String::from_utf8(response).expect("HTTP UTF-8");
    assert!(response.starts_with("HTTP/1.1 200 OK"), "{response}");
    assert!(response.ends_with("\r\n\r\nok"), "{response}");
}

async fn assert_websocket_round_trip(address: SocketAddr) {
    let url = format!("ws://{address}/ws");
    let (mut client, response) = connect_async(url).await.expect("WebSocket upgrade");
    assert_eq!(response.status(), 101);

    client
        .send(tungstenite::Message::Text("resize:40x120".into()))
        .await
        .expect("send text");
    assert!(matches!(
        timeout(TIMEOUT, client.next()).await,
        Ok(Some(Ok(tungstenite::Message::Text(text)))) if text == "resize:40x120"
    ));

    client
        .send(tungstenite::Message::Binary(vec![0, 1, 2, 255].into()))
        .await
        .expect("send binary");
    assert!(matches!(
        timeout(TIMEOUT, client.next()).await,
        Ok(Some(Ok(tungstenite::Message::Binary(bytes)))) if bytes.as_ref() == [0, 1, 2, 255]
    ));

    client.close(None).await.expect("close WebSocket");
}

async fn assert_bounded_backpressure() {
    let (tx, mut rx) = mpsc::channel(1);
    tx.send(1_u8).await.expect("fill bounded channel");
    let blocked = tokio::spawn(async move { tx.send(2_u8).await });
    sleep(Duration::from_millis(30)).await;
    assert!(!blocked.is_finished(), "second send must wait for capacity");
    assert_eq!(rx.recv().await, Some(1));
    timeout(TIMEOUT, blocked)
        .await
        .expect("send unblocked")
        .expect("sender joined")
        .expect("send succeeded");
    assert_eq!(rx.recv().await, Some(2));
}

async fn run_once() {
    let mut server = start_server().await;
    assert_http_route(server.address).await;
    assert_websocket_round_trip(server.address).await;
    assert_bounded_backpressure().await;
    timeout(TIMEOUT, server.bridge_stopped.recv())
        .await
        .expect("bridge teardown timed out")
        .expect("bridge teardown notification missing");
    server.shutdown.send(()).expect("request graceful shutdown");
    timeout(TIMEOUT, server.task)
        .await
        .expect("server shutdown timed out")
        .expect("server task failed");
}

#[tokio::main]
async fn main() {
    for _ in 0..10 {
        timeout(TIMEOUT, run_once())
            .await
            .expect("web spike iteration timed out");
    }
    println!("PASS web-stack: HTTP routing, typed WS frames, bounded bridge, teardown (10/10)");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn exercises_required_web_stack_behaviors() {
        timeout(TIMEOUT, run_once()).await.expect("spike timed out");
    }
}
