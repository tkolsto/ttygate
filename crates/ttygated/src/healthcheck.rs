use std::{io, net::SocketAddr, time::Duration};

use thiserror::Error;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time,
};

const DEFAULT_ADDRESS: &str = "127.0.0.1:7681";
const REQUEST: &[u8] = b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
const MAX_RESPONSE_BYTES: u64 = 4096;

#[derive(Debug, Error)]
#[error("health check failed")]
pub struct HealthCheckError;

pub fn parse_address(value: Option<&str>) -> Result<SocketAddr, HealthCheckError> {
    let address = value
        .unwrap_or(DEFAULT_ADDRESS)
        .parse::<SocketAddr>()
        .map_err(|_| HealthCheckError)?;
    if !address.ip().is_loopback() {
        return Err(HealthCheckError);
    }
    Ok(address)
}

pub async fn check(address: SocketAddr, timeout: Duration) -> Result<(), HealthCheckError> {
    if !address.ip().is_loopback() {
        return Err(HealthCheckError);
    }
    time::timeout(timeout, check_inner(address))
        .await
        .map_err(|_| HealthCheckError)?
        .map_err(|_| HealthCheckError)
}

async fn check_inner(address: SocketAddr) -> io::Result<()> {
    let mut stream = TcpStream::connect(address).await?;
    stream.write_all(REQUEST).await?;
    let mut response = Vec::new();
    stream
        .take(MAX_RESPONSE_BYTES + 1)
        .read_to_end(&mut response)
        .await?;
    if response.len() as u64 > MAX_RESPONSE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "health response exceeded bound",
        ));
    }
    let Some(headers_end) = response.windows(4).position(|value| value == b"\r\n\r\n") else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "health response was malformed",
        ));
    };
    let headers = &response[..headers_end];
    let body = &response[headers_end + 4..];
    let Some(status_end) = headers.windows(2).position(|value| value == b"\r\n") else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "health response was malformed",
        ));
    };
    let status = &headers[..status_end];
    if !matches!(status, b"HTTP/1.1 200 OK" | b"HTTP/1.0 200 OK") || body != b"ok\n" {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "health response was not healthy",
        ));
    }
    Ok(())
}
