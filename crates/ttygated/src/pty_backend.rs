use std::{
    pin::Pin,
    process::Stdio,
    task::{Context, Poll},
};

use nix::{
    sys::signal::{Signal, killpg},
    unistd::Pid,
};
use thiserror::Error;
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    process::{Child, ChildStderr},
};

use crate::{
    config::PtyTarget,
    protocol::Resize,
    ssh::{SshClientLog, SshSpawnSpec},
};

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
                exit_status: None,
                cleanup_state: CleanupState::Running,
                #[cfg(test)]
                reaped: None,
                #[cfg(test)]
                cleanup_failures: None,
                #[cfg(test)]
                post_kill_wait_stalls: None,
                #[cfg(test)]
                group_ops: None,
            },
        })
    }

    #[allow(dead_code, reason = "the SSH lifecycle supervisor is added in Task 4")]
    pub(crate) fn spawn_ssh(spec: SshSpawnSpec, size: Resize) -> Result<RunningSsh, BackendError> {
        let (pty, pts) = pty_process::open().map_err(|_| BackendError::Unavailable)?;
        pty.resize(pty_process::Size::new(size.rows, size.cols))
            .map_err(|_| BackendError::Unavailable)?;
        let command = pty_process::Command::new(spec.executable())
            .args(spec.argv())
            .env_clear()
            .envs(spec.environment())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        let mut child = command.spawn(pts).map_err(|_| BackendError::Unavailable)?;
        let raw_stderr = child
            .stderr
            .take()
            .expect("piped stderr is a Tokio child invariant");
        let pid = Pid::from_raw(
            i32::try_from(child.id().expect("spawned child has a process id"))
                .expect("Unix process ids fit in i32"),
        );
        let client_log = spec.into_client_log();
        let (reader, writer) = pty.into_split();
        Ok(RunningSsh {
            reader: PtyReader(reader),
            writer: PtyWriter(writer),
            child: PtyChild {
                inner: child,
                process_group: pid,
                exit_status: None,
                cleanup_state: CleanupState::Running,
                #[cfg(test)]
                reaped: None,
                #[cfg(test)]
                cleanup_failures: None,
                #[cfg(test)]
                post_kill_wait_stalls: None,
                #[cfg(test)]
                group_ops: None,
            },
            raw_stderr,
            client_log,
        })
    }
}

#[allow(dead_code, reason = "the SSH lifecycle supervisor is added in Task 4")]
pub(crate) struct RunningSsh {
    reader: PtyReader,
    writer: PtyWriter,
    child: PtyChild,
    raw_stderr: ChildStderr,
    client_log: SshClientLog,
}

impl std::fmt::Debug for RunningSsh {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RunningSsh")
            .field("process_group", &self.child.process_group)
            .finish_non_exhaustive()
    }
}

impl RunningSsh {
    #[allow(dead_code, reason = "the SSH lifecycle supervisor is added in Task 4")]
    pub(crate) fn into_parts(self) -> (PtyReader, PtyWriter, PtyChild, ChildStderr, SshClientLog) {
        (
            self.reader,
            self.writer,
            self.child,
            self.raw_stderr,
            self.client_log,
        )
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

    #[cfg(test)]
    pub(crate) fn observe_reap(&mut self, reaped: std::sync::Arc<std::sync::atomic::AtomicBool>) {
        self.child.reaped = Some(reaped);
    }

    #[cfg(test)]
    pub(crate) fn inject_cleanup_failures(
        &mut self,
        failures: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    ) {
        self.child.cleanup_failures = Some(failures);
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
    exit_status: Option<std::process::ExitStatus>,
    cleanup_state: CleanupState,
    #[cfg(test)]
    reaped: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
    #[cfg(test)]
    cleanup_failures: Option<std::sync::Arc<std::sync::atomic::AtomicUsize>>,
    #[cfg(test)]
    post_kill_wait_stalls: Option<std::sync::Arc<std::sync::atomic::AtomicUsize>>,
    #[cfg(test)]
    group_ops: Option<std::sync::Arc<TestGroupOps>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CleanupState {
    Running,
    ExitObservedUnreaped,
    FinalSignalAttempted,
    Reaped,
}

#[cfg(test)]
#[derive(Default)]
struct TestGroupOps {
    final_signals: std::sync::atomic::AtomicUsize,
    probes: std::sync::atomic::AtomicUsize,
    present_probes: std::sync::atomic::AtomicUsize,
    nonzero_after_reap: std::sync::atomic::AtomicBool,
    operations: std::sync::Mutex<Vec<TestGroupOperation>>,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TestGroupOperation {
    Observe,
    Hup,
    Kill,
    Reap,
    Probe,
}

impl PtyChild {
    pub(crate) async fn wait(&mut self) -> Result<std::process::ExitStatus, BackendError> {
        if let Some(status) = self.exit_status {
            return Ok(status);
        }
        let status = self
            .inner
            .wait()
            .await
            .map_err(|_| BackendError::Unavailable)?;
        self.exit_status = Some(status);
        self.cleanup_state = CleanupState::Reaped;
        #[cfg(test)]
        self.record_group_operation(TestGroupOperation::Reap);
        Ok(status)
    }

    pub(crate) async fn wait_for_exit_observed(&mut self) -> Result<(), BackendError> {
        loop {
            if self.poll_exit_observed()? {
                return Ok(());
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }

    fn poll_exit_observed(&mut self) -> Result<bool, BackendError> {
        if self.cleanup_state != CleanupState::Running {
            return Ok(true);
        }
        let pid = rustix::process::Pid::from_raw(self.process_group.as_raw())
            .ok_or(BackendError::Unavailable)?;
        let observed = rustix::process::waitid(
            rustix::process::WaitId::Pid(pid),
            rustix::process::WaitIdOptions::EXITED
                | rustix::process::WaitIdOptions::NOHANG
                | rustix::process::WaitIdOptions::NOWAIT,
        )
        .map_err(|_| BackendError::Unavailable)?
        .is_some();
        if observed {
            self.cleanup_state = CleanupState::ExitObservedUnreaped;
            #[cfg(test)]
            self.record_group_operation(TestGroupOperation::Observe);
        }
        Ok(observed)
    }

    pub(crate) async fn terminate(
        &mut self,
        grace: std::time::Duration,
    ) -> Result<std::process::ExitStatus, BackendError> {
        self.terminate_with(grace, signal_group).await
    }

    async fn terminate_with(
        &mut self,
        grace: std::time::Duration,
        mut signal: impl FnMut(Pid, Signal) -> Result<(), BackendError>,
    ) -> Result<std::process::ExitStatus, BackendError> {
        // The unreaped leader pins the numeric process-group identifier.
        // Signal exactly once while that pin is held; after reap, retries may
        // only probe for ESRCH so they cannot signal a reused PGID.
        if matches!(
            self.cleanup_state,
            CleanupState::Running | CleanupState::ExitObservedUnreaped
        ) {
            #[cfg(test)]
            self.record_group_operation(TestGroupOperation::Hup);
            let _ = signal(self.process_group, Signal::SIGHUP);
            let grace_deadline = tokio::time::Instant::now() + grace;
            while self.cleanup_state == CleanupState::Running
                && tokio::time::Instant::now() < grace_deadline
            {
                let _ = self.poll_exit_observed()?;
                if self.cleanup_state == CleanupState::Running {
                    tokio::time::sleep_until(std::cmp::min(
                        grace_deadline,
                        tokio::time::Instant::now() + std::time::Duration::from_millis(10),
                    ))
                    .await;
                }
            }
            tokio::time::sleep_until(grace_deadline).await;
            self.cleanup_state = CleanupState::FinalSignalAttempted;
            #[cfg(test)]
            if let Some(ops) = &self.group_ops {
                ops.final_signals
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                if self.exit_status.is_some() {
                    ops.nonzero_after_reap
                        .store(true, std::sync::atomic::Ordering::SeqCst);
                }
            }
            #[cfg(test)]
            self.record_group_operation(TestGroupOperation::Kill);
            let _ = signal(self.process_group, Signal::SIGKILL);
        }

        let status = tokio::time::timeout(grace, self.wait_after_final_signal())
            .await
            .map_err(|_| BackendError::Unavailable)
            .and_then(std::convert::identity)?;
        self.wait_for_group_absence(grace).await?;
        #[cfg(test)]
        self.confirm_cleanup_for_test();
        Ok(status)
    }

    async fn wait_for_group_absence(&self, grace: std::time::Duration) -> Result<(), BackendError> {
        let deadline = tokio::time::Instant::now() + grace;
        loop {
            if self.process_group_absent()? {
                return Ok(());
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(BackendError::Unavailable);
            }
            tokio::time::sleep_until(std::cmp::min(
                deadline,
                tokio::time::Instant::now() + std::time::Duration::from_millis(10),
            ))
            .await;
        }
    }

    async fn wait_after_final_signal(&mut self) -> Result<std::process::ExitStatus, BackendError> {
        #[cfg(test)]
        if let Some(stalls) = &self.post_kill_wait_stalls
            && stalls
                .fetch_update(
                    std::sync::atomic::Ordering::SeqCst,
                    std::sync::atomic::Ordering::SeqCst,
                    |remaining| remaining.checked_sub(1),
                )
                .is_ok()
        {
            std::future::pending::<()>().await;
        }
        self.wait().await
    }

    fn process_group_absent(&self) -> Result<bool, BackendError> {
        #[cfg(test)]
        if let Some(ops) = &self.group_ops {
            self.record_group_operation(TestGroupOperation::Probe);
            ops.probes.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let remaining = ops.present_probes.load(std::sync::atomic::Ordering::SeqCst);
            if remaining != 0 {
                ops.present_probes
                    .fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
                return Ok(false);
            }
            return Ok(true);
        }
        #[cfg(test)]
        if let Some(failures) = &self.cleanup_failures {
            let remaining = failures.load(std::sync::atomic::Ordering::SeqCst);
            if remaining != 0 {
                if remaining != usize::MAX {
                    failures.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
                }
                return Ok(false);
            }
        }
        match killpg(self.process_group, None) {
            Err(nix::errno::Errno::ESRCH) => Ok(true),
            Ok(()) | Err(nix::errno::Errno::EPERM) => Ok(false),
            Err(_) => Err(BackendError::Unavailable),
        }
    }

    #[cfg(test)]
    fn record_group_operation(&self, operation: TestGroupOperation) {
        if let Some(ops) = &self.group_ops {
            ops.operations
                .lock()
                .expect("test group operation recorder")
                .push(operation);
        }
    }

    #[cfg(test)]
    fn confirm_cleanup_for_test(&self) {
        if let Some(reaped) = &self.reaped {
            reaped.store(true, std::sync::atomic::Ordering::SeqCst);
        }
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

#[cfg(test)]
mod tests {
    use std::{path::PathBuf, time::Duration};

    use nix::{
        sys::signal::{Signal, kill},
        unistd::Pid,
    };
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        time::timeout,
    };

    use crate::{config::PtyTarget, protocol::Resize};

    use super::{BackendError, PtyProcessBackend, signal_group};

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

    #[tokio::test]
    async fn graceful_signal_error_is_recovered_by_successful_final_cleanup() {
        let running = PtyProcessBackend::spawn(&target(&[]), Resize::new(80, 24).unwrap())
            .expect("spawn fixture");
        let (mut reader, _writer, mut child) = running.into_parts();
        let mut output = Vec::new();
        read_until(&mut reader, &mut output, b"READY").await;
        let pid = child.process_group;
        let mut first = true;
        let result = child
            .terminate_with(Duration::from_millis(100), |group, signal| {
                signal_group(group, signal)?;
                if first && signal == Signal::SIGHUP {
                    first = false;
                    Err(BackendError::Unavailable)
                } else {
                    Ok(())
                }
            })
            .await;
        assert!(result.is_ok());
        assert_eq!(
            kill(Pid::from_raw(pid.as_raw()), None),
            Err(nix::errno::Errno::ESRCH)
        );
    }

    #[tokio::test]
    async fn final_signal_error_is_reported_after_reaping_the_child() {
        let running =
            PtyProcessBackend::spawn(&target(&["ignore-hup"]), Resize::new(80, 24).unwrap())
                .expect("spawn fixture");
        let (mut reader, _writer, mut child) = running.into_parts();
        let mut output = Vec::new();
        read_until(&mut reader, &mut output, b"READY").await;
        let pid = child.process_group;
        let result = child
            .terminate_with(Duration::from_millis(100), |group, signal| {
                if signal == Signal::SIGKILL {
                    Err(BackendError::Unavailable)
                } else {
                    signal_group(group, signal)
                }
            })
            .await;
        assert_eq!(result, Err(BackendError::Unavailable));
        signal_group(child.process_group, Signal::SIGKILL).unwrap();
        child.wait().await.unwrap();
        assert_eq!(
            kill(Pid::from_raw(pid.as_raw()), None),
            Err(nix::errno::Errno::ESRCH)
        );
    }

    #[tokio::test]
    async fn post_sigkill_child_wait_is_bounded_and_retryable() {
        let running =
            PtyProcessBackend::spawn(&target(&["ignore-hup"]), Resize::new(80, 24).unwrap())
                .expect("spawn fixture");
        let (mut reader, _writer, mut child) = running.into_parts();
        let mut output = Vec::new();
        read_until(&mut reader, &mut output, b"READY").await;
        child.post_kill_wait_stalls =
            Some(std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(1)));

        let result = timeout(
            Duration::from_millis(300),
            child.terminate_with(Duration::from_millis(50), signal_group),
        )
        .await;
        let retry = timeout(
            Duration::from_millis(300),
            child.terminate_with(Duration::from_millis(50), signal_group),
        )
        .await;
        let cached_retry = timeout(
            Duration::from_millis(300),
            child.terminate_with(Duration::from_millis(50), signal_group),
        )
        .await;

        assert!(
            matches!(result, Ok(Err(BackendError::Unavailable))),
            "post-SIGKILL child wait must return a bounded retryable error"
        );
        assert!(
            matches!(retry, Ok(Ok(_))),
            "retry must reap the child after the bounded failure"
        );
        assert!(
            matches!(cached_retry, Ok(Ok(_))),
            "later retries must reuse the cached child status"
        );
    }

    #[tokio::test]
    async fn natural_exit_is_observed_then_group_signaled_before_leader_reap() {
        let target = PtyTarget {
            name: "natural-exit".to_owned(),
            executable: "/bin/sh".into(),
            argv: vec!["-c".to_owned(), "exit 23".to_owned()],
            read_only: false,
        };
        let running = PtyProcessBackend::spawn(&target, Resize::new(80, 24).unwrap())
            .expect("spawn natural-exit fixture");
        let (_reader, _writer, mut child) = running.into_parts();
        let ops = std::sync::Arc::new(super::TestGroupOps::default());
        child.group_ops = Some(std::sync::Arc::clone(&ops));

        timeout(Duration::from_secs(3), child.wait_for_exit_observed())
            .await
            .expect("natural exit observation timed out")
            .unwrap();
        let status = child
            .terminate_with(Duration::from_millis(1), |_group, _signal| Ok(()))
            .await
            .unwrap();

        assert_eq!(status.code(), Some(23));
        assert_eq!(
            *ops.operations.lock().unwrap(),
            [
                super::TestGroupOperation::Observe,
                super::TestGroupOperation::Hup,
                super::TestGroupOperation::Kill,
                super::TestGroupOperation::Reap,
                super::TestGroupOperation::Probe,
            ]
        );
    }

    #[tokio::test]
    async fn requested_teardown_observes_graceful_exit_before_final_signal_and_reap() {
        let target = PtyTarget {
            name: "requested-exit".to_owned(),
            executable: "/bin/sleep".into(),
            argv: vec!["300".to_owned()],
            read_only: false,
        };
        let running = PtyProcessBackend::spawn(&target, Resize::new(80, 24).unwrap())
            .expect("spawn requested-exit fixture");
        let (_reader, _writer, mut child) = running.into_parts();
        let ops = std::sync::Arc::new(super::TestGroupOps::default());
        child.group_ops = Some(std::sync::Arc::clone(&ops));

        child
            .terminate_with(Duration::from_millis(100), signal_group)
            .await
            .unwrap();

        assert_eq!(
            *ops.operations.lock().unwrap(),
            [
                super::TestGroupOperation::Hup,
                super::TestGroupOperation::Observe,
                super::TestGroupOperation::Kill,
                super::TestGroupOperation::Reap,
                super::TestGroupOperation::Probe,
            ]
        );
    }

    #[tokio::test]
    async fn reaped_group_cleanup_only_probes_and_never_resignals_reused_pgid() {
        let running =
            PtyProcessBackend::spawn(&target(&["ignore-hup"]), Resize::new(80, 24).unwrap())
                .expect("spawn fixture");
        let (mut reader, _writer, mut child) = running.into_parts();
        let mut output = Vec::new();
        read_until(&mut reader, &mut output, b"READY").await;
        let ops = std::sync::Arc::new(super::TestGroupOps::default());
        ops.present_probes
            .store(3, std::sync::atomic::Ordering::SeqCst);
        child.group_ops = Some(std::sync::Arc::clone(&ops));

        child
            .terminate_with(Duration::from_millis(50), signal_group)
            .await
            .unwrap();

        assert_eq!(
            ops.final_signals.load(std::sync::atomic::Ordering::SeqCst),
            1
        );
        assert_eq!(ops.probes.load(std::sync::atomic::Ordering::SeqCst), 4);
        assert!(
            !ops.nonzero_after_reap
                .load(std::sync::atomic::Ordering::SeqCst)
        );
    }
}
