use std::{
    pin::Pin,
    task::{Context, Poll},
};

use nix::{
    sys::signal::{Signal, kill, killpg},
    unistd::Pid,
};
use thiserror::Error;
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    process::Child,
};

use crate::{config::PtyTarget, protocol::Resize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub(crate) enum BackendError {
    #[error("The terminal backend is unavailable.")]
    Unavailable,
}

pub(crate) struct PtyProcessBackend;

impl PtyProcessBackend {
    pub(crate) fn spawn(target: &PtyTarget, size: Resize) -> Result<RunningPty, BackendError> {
        let (pty, pts) = pty_process::open().map_err(|_| BackendError::Unavailable)?;
        pty.resize(pty_process::Size::new(size.rows, size.cols))
            .map_err(|_| BackendError::Unavailable)?;
        let command = pty_process::Command::new(&target.executable)
            .args(&target.argv)
            .kill_on_drop(true);
        let child = command.spawn(pts).map_err(|_| BackendError::Unavailable)?;
        let pid = child
            .id()
            .and_then(|pid| i32::try_from(pid).ok())
            .map(Pid::from_raw)
            .ok_or(BackendError::Unavailable)?;
        let (reader, writer) = pty.into_split();
        Ok(RunningPty {
            reader: PtyReader(reader),
            writer: PtyWriter(writer),
            child: PtyChild {
                inner: child,
                process_group: pid,
            },
        })
    }
}

pub(crate) struct RunningPty {
    reader: PtyReader,
    writer: PtyWriter,
    child: PtyChild,
}

impl std::fmt::Debug for RunningPty {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RunningPty")
            .field("process_group", &self.child.process_group)
            .finish_non_exhaustive()
    }
}

impl RunningPty {
    pub(crate) fn into_parts(self) -> (PtyReader, PtyWriter, PtyChild) {
        (self.reader, self.writer, self.child)
    }
}

pub(crate) struct PtyReader(pty_process::OwnedReadPty);

impl AsyncRead for PtyReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_read(context, buffer)
    }
}

pub(crate) struct PtyWriter(pty_process::OwnedWritePty);

impl PtyWriter {
    pub(crate) fn resize(&self, size: Resize) -> Result<(), BackendError> {
        self.0
            .resize(pty_process::Size::new(size.rows, size.cols))
            .map_err(|_| BackendError::Unavailable)
    }
}

impl AsyncWrite for PtyWriter {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(context, buffer)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(context)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(context)
    }
}

pub(crate) struct PtyChild {
    inner: Child,
    process_group: Pid,
}

impl PtyChild {
    pub(crate) async fn wait(&mut self) -> Result<std::process::ExitStatus, BackendError> {
        self.inner
            .wait()
            .await
            .map_err(|_| BackendError::Unavailable)
    }

    pub(crate) fn try_wait(&mut self) -> Result<Option<std::process::ExitStatus>, BackendError> {
        self.inner.try_wait().map_err(|_| BackendError::Unavailable)
    }

    pub(crate) async fn terminate(
        &mut self,
        grace: std::time::Duration,
    ) -> Result<std::process::ExitStatus, BackendError> {
        signal_group(self.process_group, Signal::SIGHUP)?;
        match tokio::time::timeout(grace, self.inner.wait()).await {
            Ok(result) => {
                let status = result.map_err(|_| BackendError::Unavailable)?;
                kill_group_if_present(self.process_group)?;
                Ok(status)
            }
            Err(_) => {
                signal_group(self.process_group, Signal::SIGKILL)?;
                self.inner
                    .wait()
                    .await
                    .map_err(|_| BackendError::Unavailable)
            }
        }
    }

    pub(crate) async fn cleanup_group_after_exit(
        &self,
        grace: std::time::Duration,
    ) -> Result<(), BackendError> {
        signal_group(self.process_group, Signal::SIGHUP)?;
        tokio::time::sleep(grace).await;
        kill_group_if_present(self.process_group)
    }

    #[cfg(test)]
    async fn terminate_for_test(&mut self) {
        self.terminate(std::time::Duration::from_millis(100))
            .await
            .expect("fixture teardown");
    }
}

fn signal_group(process_group: Pid, signal: Signal) -> Result<(), BackendError> {
    match killpg(process_group, signal) {
        Ok(()) | Err(nix::errno::Errno::ESRCH) => Ok(()),
        Err(_) => Err(BackendError::Unavailable),
    }
}

fn group_exists(process_group: Pid) -> Result<bool, BackendError> {
    match kill(Pid::from_raw(-process_group.as_raw()), None) {
        Ok(()) | Err(nix::errno::Errno::EPERM) => Ok(true),
        Err(nix::errno::Errno::ESRCH) => Ok(false),
        Err(_) => Err(BackendError::Unavailable),
    }
}

fn kill_group_if_present(process_group: Pid) -> Result<(), BackendError> {
    if group_exists(process_group)? {
        signal_group(process_group, Signal::SIGKILL)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{path::PathBuf, time::Duration};

    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        time::timeout,
    };

    use crate::{config::PtyTarget, protocol::Resize};

    use super::PtyProcessBackend;

    const WAIT: Duration = Duration::from_secs(3);

    fn fixture() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/pty_child.sh")
    }

    fn target(arguments: &[&str]) -> PtyTarget {
        PtyTarget {
            name: "fixture".to_owned(),
            executable: fixture(),
            argv: arguments.iter().map(|value| (*value).to_owned()).collect(),
            read_only: false,
        }
    }

    async fn read_until(reader: &mut super::PtyReader, output: &mut Vec<u8>, marker: &[u8]) {
        let mut buffer = [0_u8; 1024];
        timeout(WAIT, async {
            while !output.windows(marker.len()).any(|window| window == marker) {
                let count = reader.read(&mut buffer).await.expect("PTY read");
                assert_ne!(count, 0, "PTY closed before marker");
                output.extend_from_slice(&buffer[..count]);
            }
        })
        .await
        .expect("PTY marker timed out");
    }

    #[tokio::test]
    async fn configured_argv_executes_directly_without_shell_interpretation() {
        let resize = Resize::new(80, 24).unwrap();
        let running = PtyProcessBackend::spawn(&target(&["$(touch nope)", "two words"]), resize)
            .expect("spawn fixture");
        let (mut reader, _writer, mut child) = running.into_parts();
        let mut output = Vec::new();
        read_until(&mut reader, &mut output, b"READY").await;
        assert!(
            output
                .windows(b"ARG1:[$(touch nope)]".len())
                .any(|window| window == b"ARG1:[$(touch nope)]")
        );
        assert!(
            output
                .windows(b"ARG2:[two words]".len())
                .any(|window| window == b"ARG2:[two words]")
        );
        child.terminate_for_test().await;
    }

    #[tokio::test]
    async fn terminal_input_output_and_resize_reach_the_child() {
        let resize = Resize::new(80, 24).unwrap();
        let running = PtyProcessBackend::spawn(&target(&[]), resize).expect("spawn fixture");
        let (mut reader, mut writer, mut child) = running.into_parts();
        let mut output = Vec::new();
        read_until(&mut reader, &mut output, b"INITIAL:24 80").await;

        writer.resize(Resize::new(132, 41).unwrap()).unwrap();
        writer.write_all(b"size\n").await.unwrap();
        writer.flush().await.unwrap();
        read_until(&mut reader, &mut output, b"RESIZED:41 132").await;

        writer.write_all(b"echo-token\n").await.unwrap();
        writer.flush().await.unwrap();
        read_until(&mut reader, &mut output, b"ECHO:echo-token").await;
        child.terminate_for_test().await;
    }

    #[tokio::test]
    async fn backend_spawn_errors_are_typed_and_safe() {
        let mut missing = target(&[]);
        missing.executable = "/definitely/not/a/real/ttygate-fixture".into();
        let error = PtyProcessBackend::spawn(&missing, Resize::new(80, 24).unwrap())
            .expect_err("missing executable must fail");
        let message = error.to_string();
        assert!(!message.contains("definitely"));
        assert!(!message.contains("ttygate-fixture"));
    }
}
