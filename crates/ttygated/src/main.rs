use std::{error::Error, path::PathBuf, time::Duration};

use ttygated::{config, healthcheck, startup};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let mut arguments = std::env::args_os().skip(1);
    let first = arguments.next();
    if first.as_deref() == Some(std::ffi::OsStr::new("--health-check")) {
        let address = arguments
            .next()
            .map(|value| {
                value
                    .into_string()
                    .map_err(|_| healthcheck::HealthCheckError)
            })
            .transpose()?;
        if arguments.next().is_some() {
            return Err(healthcheck::HealthCheckError.into());
        }
        let address = healthcheck::parse_address(address.as_deref())?;
        healthcheck::check(address, Duration::from_secs(3)).await?;
        return Ok(());
    }
    let config_path = first
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("ttygate.toml"));
    let config = config::load(&config_path)?;
    startup::start(&config).await?;
    Ok(())
}
