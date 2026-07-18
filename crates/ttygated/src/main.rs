use std::{error::Error, path::PathBuf};

use ttygated::{config, startup};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let config_path = std::env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("ttygate.toml"));
    let config = config::load(&config_path)?;
    startup::start(&config).await?;
    Ok(())
}
