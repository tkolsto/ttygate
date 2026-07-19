use std::{env, time::Duration};

use sd_notify::NotifyState;
use thiserror::Error;
use tokio::task::JoinHandle;

const MINIMUM_INTERVAL: Duration = Duration::from_micros(1);

#[derive(Debug, Error)]
#[error("service manager notification failed")]
pub struct ServiceManagerError {
    #[source]
    source: std::io::Error,
}

pub fn notify_ready() -> Result<(), ServiceManagerError> {
    if env::var_os("NOTIFY_SOCKET").is_none() {
        return Ok(());
    }
    sd_notify::notify(&[NotifyState::Ready]).map_err(|source| ServiceManagerError { source })
}

pub fn notification_interval(watchdog_timeout: Duration) -> Duration {
    watchdog_timeout
        .checked_div(2)
        .unwrap_or(MINIMUM_INTERVAL)
        .max(MINIMUM_INTERVAL)
}

pub fn watchdog_interval() -> Option<Duration> {
    sd_notify::watchdog_enabled().map(notification_interval)
}

pub fn spawn_watchdog() -> Option<WatchdogTask> {
    let interval = watchdog_interval()?;
    Some(WatchdogTask(tokio::spawn(async move {
        loop {
            tokio::time::sleep(interval).await;
            if sd_notify::notify(&[NotifyState::Watchdog]).is_err() {
                break;
            }
        }
    })))
}

pub struct WatchdogTask(JoinHandle<()>);

impl Drop for WatchdogTask {
    fn drop(&mut self) {
        self.0.abort();
    }
}
