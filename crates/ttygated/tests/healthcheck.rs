use std::{net::SocketAddr, time::Duration};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

async fn fixture(response: &'static [u8]) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = [0_u8; 256];
        let read = stream.read(&mut request).await.unwrap();
        assert_eq!(
            &request[..read],
            b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
        );
        stream.write_all(response).await.unwrap();
    });
    address
}

#[tokio::test]
async fn exact_healthz_success_is_accepted() {
    let address = fixture(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nok\n").await;
    ttygated::healthcheck::check(address, Duration::from_secs(1))
        .await
        .unwrap();
}

#[tokio::test]
async fn non_success_malformed_oversize_and_wrong_body_fail_closed() {
    for response in [
        b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 3\r\n\r\nok\n".as_slice(),
        b"not http".as_slice(),
        b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nnope".as_slice(),
        &[b'x'; 4097],
    ] {
        let address = fixture(response).await;
        let error = ttygated::healthcheck::check(address, Duration::from_secs(1))
            .await
            .unwrap_err();
        assert_eq!(error.to_string(), "health check failed");
    }
}

#[tokio::test]
async fn timeout_and_non_loopback_destinations_fail_without_reflection() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let timeout_error = ttygated::healthcheck::check(address, Duration::from_millis(10))
        .await
        .unwrap_err();
    assert_eq!(timeout_error.to_string(), "health check failed");

    let hostile: SocketAddr = "192.0.2.55:65535".parse().unwrap();
    let error = ttygated::healthcheck::check(hostile, Duration::from_secs(1))
        .await
        .unwrap_err();
    assert_eq!(error.to_string(), "health check failed");
    assert!(!error.to_string().contains("192.0.2.55"));
}

#[test]
fn cli_address_is_loopback_only_and_has_a_stable_default() {
    assert_eq!(
        ttygated::healthcheck::parse_address(None).unwrap(),
        "127.0.0.1:7681".parse::<SocketAddr>().unwrap()
    );
    assert_eq!(
        ttygated::healthcheck::parse_address(Some("127.0.0.1:9000")).unwrap(),
        "127.0.0.1:9000".parse::<SocketAddr>().unwrap()
    );
    for invalid in ["0.0.0.0:7681", "192.0.2.1:7681", "localhost:7681", "secret"] {
        let error = ttygated::healthcheck::parse_address(Some(invalid)).unwrap_err();
        assert_eq!(error.to_string(), "health check failed");
        assert!(!error.to_string().contains(invalid));
    }
}
