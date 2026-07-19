#![cfg(unix)]

use std::{
    os::unix::net::UnixDatagram,
    sync::{Mutex, OnceLock},
    time::Duration,
};

fn environment_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[test]
fn readiness_notification_is_exact_and_absence_is_nonfatal() {
    let _guard = environment_lock();
    let directory = tempfile::tempdir().unwrap();
    let socket_path = directory.path().join("notify.sock");
    let socket = UnixDatagram::bind(&socket_path).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();

    // SAFETY: this integration test process serializes every environment
    // mutation through environment_lock and restores the variable below.
    unsafe { std::env::set_var("NOTIFY_SOCKET", &socket_path) };
    ttygated::service_manager::notify_ready().unwrap();
    let mut message = [0_u8; 64];
    let size = socket.recv(&mut message).unwrap();
    assert_eq!(&message[..size], b"READY=1\n");
    // SAFETY: see the serialized mutation above.
    unsafe { std::env::remove_var("NOTIFY_SOCKET") };

    ttygated::service_manager::notify_ready().unwrap();
}

#[test]
fn watchdog_uses_half_the_negotiated_interval_with_a_safe_floor() {
    assert_eq!(
        ttygated::service_manager::notification_interval(Duration::from_secs(30)),
        Duration::from_secs(15)
    );
    assert_eq!(
        ttygated::service_manager::notification_interval(Duration::from_micros(1)),
        Duration::from_micros(1)
    );
}

#[test]
fn watchdog_environment_is_disabled_or_parsed_without_reflection() {
    let _guard = environment_lock();
    // SAFETY: environment mutations are serialized within this test process.
    unsafe {
        std::env::remove_var("WATCHDOG_USEC");
        std::env::remove_var("WATCHDOG_PID");
    }
    assert_eq!(ttygated::service_manager::watchdog_interval(), None);

    // SAFETY: environment mutations are serialized within this test process.
    unsafe { std::env::set_var("WATCHDOG_USEC", "30000000") };
    assert_eq!(
        ttygated::service_manager::watchdog_interval(),
        Some(Duration::from_secs(15))
    );
    // SAFETY: environment mutations are serialized within this test process.
    unsafe { std::env::remove_var("WATCHDOG_USEC") };
}
