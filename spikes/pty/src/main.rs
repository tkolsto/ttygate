use std::{
    fs::File,
    io::{Read, Write},
    os::{fd::OwnedFd, unix::process::CommandExt},
    process::{Child, Command, Stdio},
    sync::mpsc::{Receiver, sync_channel},
    thread,
    time::Duration,
};

use nix::{
    pty::{OpenptyResult, Winsize, openpty},
    sys::signal::{Signal, killpg},
    unistd::{Pid, dup, setsid},
};
use portable_pty::{CommandBuilder, PtySize, native_pty_system};
use tokio::{io::AsyncReadExt, io::AsyncWriteExt, time::timeout};

const WAIT: Duration = Duration::from_secs(3);
const INITIAL: (u16, u16) = (24, 80);
const RESIZED: (u16, u16) = (41, 132);

#[derive(Debug)]
struct Observation {
    implementation: &'static str,
    pid: u32,
    descendant: u32,
    initial: (u16, u16),
    resized: (u16, u16),
    reaped: bool,
    orphan_free: bool,
}

fn fixture() -> String {
    format!("{}/fixtures/child.sh", env!("CARGO_MANIFEST_DIR"))
}

fn parse_value(output: &str, key: &str) -> Option<u32> {
    output.lines().find_map(|line| {
        let clean = line.trim().trim_end_matches('\r');
        clean
            .strip_prefix(key)
            .and_then(|value| value.trim().parse().ok())
    })
}

fn parse_size(output: &str, key: &str) -> Option<(u16, u16)> {
    output.lines().find_map(|line| {
        let clean = line.trim().trim_end_matches('\r');
        let value = clean.strip_prefix(key)?.trim();
        let mut parts = value.split_whitespace();
        Some((parts.next()?.parse().ok()?, parts.next()?.parse().ok()?))
    })
}

fn read_until(rx: &Receiver<Vec<u8>>, output: &mut String, marker: &str) {
    while !output.contains(marker) {
        let bytes = rx.recv_timeout(WAIT).expect("PTY output timed out");
        output.push_str(&String::from_utf8_lossy(&bytes));
    }
}

fn bounded_reader(mut reader: impl Read + Send + 'static) -> Receiver<Vec<u8>> {
    let (tx, rx) = sync_channel(1);
    thread::spawn(move || {
        let mut buffer = [0_u8; 1024];
        loop {
            match reader.read(&mut buffer) {
                Ok(0) | Err(_) => break,
                Ok(count) => {
                    if tx.send(buffer[..count].to_vec()).is_err() {
                        break;
                    }
                }
            }
        }
    });
    rx
}

fn process_exists(pid: u32) -> bool {
    // SAFETY: kill with signal 0 performs an existence/permission check only.
    let result = unsafe { libc::kill(pid as i32, 0) };
    result == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

fn terminate_group(pid: u32) {
    let _ = killpg(Pid::from_raw(pid as i32), Signal::SIGHUP);
    thread::sleep(Duration::from_millis(30));
    if process_exists(pid) {
        let _ = killpg(Pid::from_raw(pid as i32), Signal::SIGKILL);
    }
}

fn verify(observation: &Observation) {
    assert_eq!(observation.initial, INITIAL, "{observation:?}");
    assert_eq!(observation.resized, RESIZED, "{observation:?}");
    assert!(observation.reaped, "{observation:?}");
    assert!(observation.orphan_free, "{observation:?}");
    assert!(
        !process_exists(observation.pid),
        "child remains: {observation:?}"
    );
    assert!(
        !process_exists(observation.descendant),
        "descendant remains: {observation:?}"
    );
}

fn portable_experiment() -> Observation {
    let system = native_pty_system();
    let pair = system
        .openpty(PtySize {
            rows: INITIAL.0,
            cols: INITIAL.1,
            pixel_width: 0,
            pixel_height: 0,
        })
        .expect("portable-pty open");
    let command = CommandBuilder::new(fixture());
    let mut child = pair.slave.spawn_command(command).expect("spawn");
    drop(pair.slave);
    let pid = child.process_id().expect("child PID");
    let rx = bounded_reader(pair.master.try_clone_reader().expect("clone reader"));
    let mut writer = pair.master.take_writer().expect("take writer");
    let mut output = String::new();
    read_until(&rx, &mut output, "READY");
    pair.master
        .resize(PtySize {
            rows: RESIZED.0,
            cols: RESIZED.1,
            pixel_width: 0,
            pixel_height: 0,
        })
        .expect("portable resize");
    writer.write_all(b"size\n").expect("write size command");
    writer.flush().expect("flush");
    read_until(&rx, &mut output, "RESIZED:");
    let descendant = parse_value(&output, "DESC:").expect("descendant PID");
    terminate_group(pid);
    let _ = child.kill();
    let reaped = child.wait().is_ok();
    thread::sleep(Duration::from_millis(30));
    Observation {
        implementation: "portable-pty",
        pid,
        descendant,
        initial: parse_size(&output, "INITIAL:").expect("initial size"),
        resized: parse_size(&output, "RESIZED:").expect("resized size"),
        reaped,
        orphan_free: !process_exists(pid) && !process_exists(descendant),
    }
}

async fn pty_process_experiment() -> Observation {
    let (mut pty, pts) = pty_process::open().expect("pty-process open");
    pty.resize(pty_process::Size::new(INITIAL.0, INITIAL.1))
        .expect("initial resize");
    let mut command = pty_process::Command::new(fixture());
    command = command.kill_on_drop(true);
    let mut child = command.spawn(pts).expect("pty-process spawn");
    let pid = child.id().expect("child PID");
    let mut output = String::new();
    let mut buffer = [0_u8; 1024];
    while !output.contains("READY") {
        let count = timeout(WAIT, pty.read(&mut buffer))
            .await
            .expect("PTY output timed out")
            .expect("PTY read");
        output.push_str(&String::from_utf8_lossy(&buffer[..count]));
    }
    pty.resize(pty_process::Size::new(RESIZED.0, RESIZED.1))
        .expect("resize");
    pty.write_all(b"size\n").await.expect("write size command");
    while !output.contains("RESIZED:") {
        let count = timeout(WAIT, pty.read(&mut buffer))
            .await
            .expect("PTY output timed out")
            .expect("PTY read");
        output.push_str(&String::from_utf8_lossy(&buffer[..count]));
    }
    let descendant = parse_value(&output, "DESC:").expect("descendant PID");
    terminate_group(pid);
    let _ = child.kill().await;
    let reaped = timeout(WAIT, child.wait())
        .await
        .is_ok_and(|result| result.is_ok());
    tokio::time::sleep(Duration::from_millis(30)).await;
    Observation {
        implementation: "pty-process",
        pid,
        descendant,
        initial: parse_size(&output, "INITIAL:").expect("initial size"),
        resized: parse_size(&output, "RESIZED:").expect("resized size"),
        reaped,
        orphan_free: !process_exists(pid) && !process_exists(descendant),
    }
}

fn direct_spawn(slave: OwnedFd) -> Child {
    let stdout = dup(&slave).expect("dup stdout");
    let stderr = dup(&slave).expect("dup stderr");
    let mut command = Command::new(fixture());
    command
        .stdin(Stdio::from(slave))
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr));
    // SAFETY: this deliberately demonstrates the direct approach's unsafe
    // pre-exec burden. Only async-signal-safe syscalls run between fork/exec.
    unsafe {
        command.pre_exec(|| {
            setsid().map_err(std::io::Error::from)?;
            if libc::ioctl(libc::STDIN_FILENO, libc::TIOCSCTTY.into(), 0) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    command.spawn().expect("direct spawn")
}

fn set_direct_size(master: &File, rows: u16, cols: u16) {
    use std::os::fd::AsRawFd;
    let size = libc::winsize {
        ws_row: rows,
        ws_col: cols,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    // SAFETY: master is an owned, open PTY descriptor and size is initialized.
    let result = unsafe { libc::ioctl(master.as_raw_fd(), libc::TIOCSWINSZ, &size) };
    assert_eq!(
        result,
        0,
        "direct resize: {}",
        std::io::Error::last_os_error()
    );
}

fn direct_experiment() -> Observation {
    let OpenptyResult { master, slave } = openpty(
        Some(&Winsize {
            ws_row: INITIAL.0,
            ws_col: INITIAL.1,
            ws_xpixel: 0,
            ws_ypixel: 0,
        }),
        None,
    )
    .expect("nix openpty");
    let mut child = direct_spawn(slave);
    let pid = child.id();
    let mut master = File::from(master);
    let reader = master.try_clone().expect("clone master");
    let rx = bounded_reader(reader);
    let mut output = String::new();
    read_until(&rx, &mut output, "READY");
    set_direct_size(&master, RESIZED.0, RESIZED.1);
    master.write_all(b"size\n").expect("write size command");
    master.flush().expect("flush");
    read_until(&rx, &mut output, "RESIZED:");
    let descendant = parse_value(&output, "DESC:").expect("descendant PID");
    terminate_group(pid);
    let _ = child.kill();
    let reaped = child.wait().is_ok();
    thread::sleep(Duration::from_millis(30));
    Observation {
        implementation: "direct-nix-libc",
        pid,
        descendant,
        initial: parse_size(&output, "INITIAL:").expect("initial size"),
        resized: parse_size(&output, "RESIZED:").expect("resized size"),
        reaped,
        orphan_free: !process_exists(pid) && !process_exists(descendant),
    }
}

#[tokio::main]
async fn main() {
    let portable = portable_experiment();
    verify(&portable);
    let direct = direct_experiment();
    verify(&direct);
    for _ in 0..20 {
        let asynchronous = pty_process_experiment().await;
        verify(&asynchronous);
    }
    println!(
        "PASS PTY: {}, {}, pty-process resize/kill/reap/orphan-free (20/20)",
        portable.implementation, direct.implementation
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_fixture_output() {
        let output = "PID:10\r\nDESC:11\r\nINITIAL:24 80\r\nRESIZED:41 132\r\n";
        assert_eq!(parse_value(output, "PID:"), Some(10));
        assert_eq!(parse_size(output, "INITIAL:"), Some(INITIAL));
        assert_eq!(parse_size(output, "RESIZED:"), Some(RESIZED));
    }
}
