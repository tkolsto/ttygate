use std::{error::Error, path::PathBuf};

use tokio::net::TcpListener;
use ttygated::{
    config,
    server::{self, AppState},
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let config_path = std::env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("ttygate.toml"));
    let config = config::load(&config_path)?;
    let state = AppState::from_config(&config)?;
    let listener = TcpListener::bind(config.server.bind).await?;
    server::serve(listener, state).await?;
    Ok(())
}
