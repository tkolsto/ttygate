use std::{
    ffi::OsString,
    path::{Path, PathBuf},
    process::{Command, Output},
    time::Duration,
};

use nix::{
    sys::signal::{Signal, killpg},
    unistd::Pid,
};
use tokio::{io::AsyncReadExt, io::AsyncWriteExt, time::timeout};

const WAIT: Duration = Duration::from_secs(5);

#[derive(Clone, Debug)]
struct Target {
    host: String,
    port: u16,
    user: String,
    known_hosts: PathBuf,
    identity_file: PathBuf,
}

fn ssh_argv(target: &Target, remote_command: &str, allocate_tty: bool) -> Vec<OsString> {
    let mut argv = vec![
        "-F".into(),
        "/dev/null".into(),
        "-o".into(),
        "StrictHostKeyChecking=yes".into(),
        "-o".into(),
        format!("UserKnownHostsFile={}", target.known_hosts.display()).into(),
        "-o".into(),
        "BatchMode=yes".into(),
        "-o".into(),
        "IdentitiesOnly=yes".into(),
        "-o".into(),
        format!("IdentityFile={}", target.identity_file.display()).into(),
        "-o".into(),
        "PasswordAuthentication=no".into(),
        "-o".into(),
        "KbdInteractiveAuthentication=no".into(),
        "-o".into(),
        "PreferredAuthentications=publickey".into(),
        "-o".into(),
        "LogLevel=ERROR".into(),
        "-p".into(),
        target.port.to_string().into(),
    ];
    if allocate_tty {
        argv.push("-tt".into());
    }
    argv.push(format!("{}@{}", target.user, target.host).into());
    argv.push(remote_command.into());
    argv
}

fn run_ssh(target: &Target, command: &str) -> Output {
    Command::new("ssh")
        .args(ssh_argv(target, command, false))
        .output()
        .expect("run system ssh")
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn assert_success(target: &Target) {
    let output = run_ssh(target, "printf TTYGATE_SSH_OK");
    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(output.stdout, b"TTYGATE_SSH_OK");
}

fn assert_exit_status(target: &Target) {
    let output = run_ssh(target, "exit 7");
    assert_eq!(output.status.code(), Some(7), "{}", stderr(&output));
}

fn assert_unknown_host(target: &Target) {
    let output = run_ssh(target, "true");
    let error = stderr(&output);
    assert!(!output.status.success());
    assert!(
        error.contains("Host key verification failed") || error.contains("No ED25519 host key"),
        "unexpected unknown-host error: {error}"
    );
}

fn assert_host_key_mismatch(target: &Target) {
    let output = run_ssh(target, "true");
    let error = stderr(&output);
    assert!(!output.status.success());
    assert!(
        error.contains("REMOTE HOST IDENTIFICATION HAS CHANGED")
            || error.contains("Host key verification failed"),
        "unexpected mismatch error: {error}"
    );
}

fn assert_connection_failure(target: &Target) {
    let output = run_ssh(target, "true");
    let error = stderr(&output);
    assert!(!output.status.success());
    assert!(
        error.contains("Connection refused") || error.contains("connect to host"),
        "unexpected connection error: {error}"
    );
}

fn process_exists(pid: u32) -> bool {
    // SAFETY: signal 0 checks existence without delivering a signal.
    let result = unsafe { libc::kill(pid as i32, 0) };
    result == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

async fn read_until(pty: &mut pty_process::Pty, output: &mut String, marker: &str) {
    let mut buffer = [0_u8; 1024];
    while !output.contains(marker) {
        let count = timeout(WAIT, pty.read(&mut buffer))
            .await
            .expect("SSH PTY read timed out")
            .expect("SSH PTY read failed");
        assert_ne!(count, 0, "SSH PTY closed before {marker}: {output}");
        output.push_str(&String::from_utf8_lossy(&buffer[..count]));
    }
}

async fn assert_resize_and_teardown(target: &Target) {
    let (mut pty, pts) = pty_process::open().expect("open SSH PTY");
    pty.resize(pty_process::Size::new(24, 80))
        .expect("initial PTY size");
    let remote = "printf 'INITIAL:'; stty size; printf 'READY\\n'; read line; printf 'RESIZED:'; stty size; sleep 300";
    let mut command = pty_process::Command::new("ssh");
    command = command
        .args(ssh_argv(target, remote, true))
        .kill_on_drop(true);
    let mut child = command.spawn(pts).expect("spawn SSH in PTY");
    let pid = child.id().expect("SSH PID");
    let mut output = String::new();
    read_until(&mut pty, &mut output, "READY").await;
    assert!(output.contains("INITIAL:24 80"), "{output}");
    pty.resize(pty_process::Size::new(41, 132))
        .expect("resize SSH PTY");
    pty.write_all(b"continue\n")
        .await
        .expect("write remote PTY");
    read_until(&mut pty, &mut output, "RESIZED:").await;
    read_until(&mut pty, &mut output, "RESIZED:41 132").await;
    let _ = killpg(Pid::from_raw(pid as i32), Signal::SIGHUP);
    tokio::time::sleep(Duration::from_millis(50)).await;
    if process_exists(pid) {
        let _ = killpg(Pid::from_raw(pid as i32), Signal::SIGKILL);
    }
    let _ = child.kill().await;
    timeout(WAIT, child.wait())
        .await
        .expect("SSH wait timed out")
        .expect("SSH wait failed");
    assert!(!process_exists(pid), "local ssh child remains");
}

fn target(args: &[String], known_hosts: &Path, port: u16) -> Target {
    Target {
        host: "127.0.0.1".into(),
        port,
        user: "spike".into(),
        known_hosts: known_hosts.to_owned(),
        identity_file: PathBuf::from(&args[2]),
    }
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    assert_eq!(
        args.len(),
        7,
        "usage: spike PORT IDENTITY KNOWN_HOSTS EMPTY_HOSTS MISMATCH_HOSTS REFUSED_PORT"
    );
    let port = args[1].parse().expect("port");
    let good = target(&args, Path::new(&args[3]), port);
    let unknown = target(&args, Path::new(&args[4]), port);
    let mismatch = target(&args, Path::new(&args[5]), port);
    let refused = target(
        &args,
        Path::new(&args[3]),
        args[6].parse().expect("refused port"),
    );

    assert_success(&good);
    assert_exit_status(&good);
    assert_unknown_host(&unknown);
    assert_host_key_mismatch(&mismatch);
    assert_connection_failure(&refused);
    assert_resize_and_teardown(&good).await;
    println!("PASS OpenSSH: strict success, unknown, mismatch, refused, exit=7, resize, teardown");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Target {
        Target {
            host: "server.example".into(),
            port: 2222,
            user: "fixed-user".into(),
            known_hosts: "/server/known_hosts".into(),
            identity_file: "/server/id".into(),
        }
    }

    #[test]
    fn argv_is_fully_server_constructed_and_pinned() {
        let argv = ssh_argv(&sample(), "true", false);
        let actual: Vec<_> = argv.iter().map(|arg| arg.to_string_lossy()).collect();
        assert!(actual.windows(2).any(|v| v == ["-F", "/dev/null"]));
        assert!(actual.contains(&"StrictHostKeyChecking=yes".into()));
        assert!(actual.contains(&"UserKnownHostsFile=/server/known_hosts".into()));
        assert!(actual.contains(&"BatchMode=yes".into()));
        assert!(actual.contains(&"IdentitiesOnly=yes".into()));
        assert!(actual.contains(&"fixed-user@server.example".into()));
        assert_eq!(actual.last(), Some(&"true".into()));
    }

    #[test]
    fn protocol_bytes_have_no_argv_api() {
        let hostile = "-oStrictHostKeyChecking=no";
        let argv = ssh_argv(&sample(), "true", false);
        assert!(!argv.iter().any(|value| value == hostile));
    }
}
