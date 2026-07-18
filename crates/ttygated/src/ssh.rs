use std::{
    collections::BTreeMap,
    ffi::OsString,
    fs::{self, File},
    future::Future,
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};

use base64::{Engine, engine::general_purpose::STANDARD};
use thiserror::Error;
use tokio::io::unix::AsyncFd;
use tokio::{io::AsyncReadExt, process::Command, time::timeout};

use crate::config::{SshTarget, Target};

pub const MAX_SSH_EXECUTABLE_BYTES: u64 = 16 * 1024 * 1024;
pub const MAX_KNOWN_HOSTS_BYTES: u64 = 4 * 1024 * 1024;
pub const MAX_IDENTITY_BYTES: u64 = 1024 * 1024;
#[allow(dead_code, reason = "the SSH lifecycle supervisor is added in Task 4")]
pub(crate) const MAX_SSH_DIAGNOSTIC_BYTES: usize = 32 * 1024;
#[allow(dead_code, reason = "the SSH lifecycle supervisor is added in Task 4")]
pub(crate) const MAX_SSH_DIAGNOSTIC_LINES: usize = 128;
#[allow(dead_code, reason = "the SSH lifecycle supervisor is added in Task 4")]
pub(crate) const MAX_SSH_DIAGNOSTIC_LINE_BYTES: usize = 1024;
const MAX_PROBE_OUTPUT_BYTES: u64 = 64 * 1024;
const MAX_IDENTITY_COMMENT_BYTES: usize = 1024;
const PROBE_TIMEOUT: Duration = Duration::from_secs(2);

// This is the ordered source of truth for the strict option vocabulary. Runtime
// argv construction must use the same keys while replacing material placeholders.
pub(crate) const STRICT_SSH_PROBE_OPTIONS: [&str; 28] = [
    "StrictHostKeyChecking=yes",
    "UserKnownHostsFile=/dev/null",
    "GlobalKnownHostsFile=/dev/null",
    "UpdateHostKeys=no",
    "CheckHostIP=yes",
    "BatchMode=yes",
    "IdentitiesOnly=yes",
    "IdentityFile=/dev/null",
    "IdentityAgent=none",
    "AddKeysToAgent=no",
    "PreferredAuthentications=publickey",
    "PubkeyAuthentication=yes",
    "PasswordAuthentication=no",
    "KbdInteractiveAuthentication=no",
    "ChallengeResponseAuthentication=no",
    "HostbasedAuthentication=no",
    "GSSAPIAuthentication=no",
    "ForwardAgent=no",
    "ForwardX11=no",
    "ForwardX11Trusted=no",
    "ClearAllForwardings=yes",
    "PermitLocalCommand=no",
    "ProxyCommand=none",
    "ProxyJump=none",
    "EnableEscapeCommandline=no",
    "EscapeChar=none",
    "CanonicalizeHostname=no",
    "RequestTTY=force",
];

fn capability_probe_argv() -> Vec<&'static str> {
    let mut argv = Vec::with_capacity(STRICT_SSH_PROBE_OPTIONS.len() * 2 + 7);
    argv.extend(["-G", "-E", "/dev/null", "-F", "/dev/null"]);
    for option in STRICT_SSH_PROBE_OPTIONS {
        argv.extend(["-o", option]);
    }
    argv.extend(["--", "ttygate-capability.invalid"]);
    argv
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum SshPreparationError {
    #[error("configured SSH executable is unsafe or unavailable")]
    ExecutableUnsafe,
    #[error("configured SSH known-hosts material is unsafe or malformed")]
    KnownHostsUnsafe,
    #[error("configured SSH identity material is unsafe, malformed, or encrypted")]
    IdentityUnsafe,
    #[error("configured SSH executable does not support the required security policy")]
    CapabilityUnsupported,
    #[error("configured SSH material changed after startup preparation")]
    MaterialChanged,
    #[error("prepared SSH targets do not exactly match the configured allowlist")]
    PreparedTargetSetMismatch,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FileSnapshot {
    device: u64,
    inode: u64,
    uid: u32,
    mode: u32,
    size: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}

impl FileSnapshot {
    fn from_metadata(metadata: &fs::Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            uid: metadata.uid(),
            mode: metadata.mode(),
            size: metadata.len(),
            modified_seconds: metadata.mtime(),
            modified_nanoseconds: metadata.mtime_nsec(),
            changed_seconds: metadata.ctime(),
            changed_nanoseconds: metadata.ctime_nsec(),
        }
    }
}

#[derive(Clone)]
pub struct PreparedSshTarget {
    name: String,
    host: String,
    port: u16,
    user_policy: crate::config::SshUserPolicy,
    read_only: bool,
    executable: PathBuf,
    executable_snapshot: FileSnapshot,
    known_hosts: PathBuf,
    known_hosts_snapshot: FileSnapshot,
    identity: PathBuf,
    identity_snapshot: FileSnapshot,
}

impl std::fmt::Debug for PreparedSshTarget {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PreparedSshTarget")
            .finish_non_exhaustive()
    }
}

impl PreparedSshTarget {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn executable(&self) -> &Path {
        &self.executable
    }

    pub fn known_hosts(&self) -> &Path {
        &self.known_hosts
    }

    pub fn identity(&self) -> &Path {
        &self.identity
    }

    pub fn recheck_before_spawn(&self) -> Result<(), SshPreparationError> {
        recheck(&self.executable, &self.executable_snapshot)?;
        recheck(&self.known_hosts, &self.known_hosts_snapshot)?;
        recheck(&self.identity, &self.identity_snapshot)
    }

    pub(crate) fn matches_target(&self, target: &SshTarget) -> bool {
        self.name == target.name
            && self.host == target.host
            && self.port == target.port
            && self.user_policy == target.user_policy
            && self.read_only == target.read_only
            && self.executable == target.ssh_executable
            && self.known_hosts == target.known_hosts
            && self.identity == target.identity_file
    }
}

#[allow(dead_code, reason = "the SSH lifecycle supervisor is added in Task 4")]
const SSH_RUNTIME_ENVIRONMENT: [(&str, &str); 3] =
    [("LANG", "C"), ("LC_ALL", "C"), ("TERM", "xterm-256color")];

#[allow(dead_code, reason = "the SSH lifecycle supervisor is added in Task 4")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub(crate) enum SshSpawnError {
    #[error("SSH target authority is unavailable.")]
    AuthorityUnavailable,
    #[error("SSH user policy denied access.")]
    PolicyDenied,
    #[error("SSH target material changed after startup.")]
    MaterialChanged,
    #[error("The SSH terminal backend is unavailable.")]
    BackendUnavailable,
}

#[allow(dead_code, reason = "the SSH lifecycle supervisor is added in Task 4")]
pub(crate) struct SshSpawnSpec {
    executable: PathBuf,
    argv: Vec<OsString>,
    prepared: PreparedSshTarget,
    client_log: SshClientLog,
}

impl std::fmt::Debug for SshSpawnSpec {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SshSpawnSpec")
            .finish_non_exhaustive()
    }
}

#[allow(dead_code, reason = "the SSH lifecycle supervisor is added in Task 4")]
impl SshSpawnSpec {
    pub(crate) fn build(
        prepared: &PreparedSshTarget,
        authenticated_user: &str,
    ) -> Result<Self, SshSpawnError> {
        let resolved_user = prepared
            .user_policy
            .resolve(authenticated_user)
            .map_err(|_| SshSpawnError::PolicyDenied)?;
        prepared
            .recheck_before_spawn()
            .map_err(|_| SshSpawnError::MaterialChanged)?;
        let client_log = SshClientLog::create()?;

        let mut argv = Vec::with_capacity(STRICT_SSH_PROBE_OPTIONS.len() * 2 + 12);
        argv.extend([OsString::from("-vv"), OsString::from("-tt")]);
        argv.extend([OsString::from("-E"), client_log.path.as_os_str().to_owned()]);
        argv.extend([OsString::from("-F"), OsString::from("/dev/null")]);
        for option in STRICT_SSH_PROBE_OPTIONS {
            let runtime_option = match option.split_once('=').map(|(key, _)| key) {
                Some("UserKnownHostsFile") => {
                    let mut value = OsString::from("UserKnownHostsFile=");
                    value.push(&prepared.known_hosts);
                    value
                }
                Some("IdentityFile") => {
                    let mut value = OsString::from("IdentityFile=");
                    value.push(&prepared.identity);
                    value
                }
                _ => OsString::from(option),
            };
            argv.extend([OsString::from("-o"), runtime_option]);
        }
        argv.extend([
            OsString::from("-p"),
            OsString::from(prepared.port.to_string()),
            OsString::from("-l"),
            OsString::from(resolved_user),
            OsString::from("--"),
            OsString::from(&prepared.host),
        ]);
        Ok(Self {
            executable: prepared.executable.clone(),
            argv,
            prepared: prepared.clone(),
            client_log,
        })
    }

    pub(crate) fn executable(&self) -> &Path {
        &self.executable
    }

    pub(crate) fn argv(&self) -> &[OsString] {
        &self.argv
    }

    pub(crate) const fn environment(&self) -> [(&'static str, &'static str); 3] {
        SSH_RUNTIME_ENVIRONMENT
    }

    #[cfg(test)]
    pub(crate) fn client_log_path_for_test(&self) -> &Path {
        &self.client_log.path
    }

    pub(crate) fn into_client_log(self) -> SshClientLog {
        self.client_log
    }
}

#[allow(dead_code, reason = "the SSH lifecycle supervisor is added in Task 4")]
pub(crate) struct SshClientLog {
    _directory: tempfile::TempDir,
    path: PathBuf,
    reader: AsyncFd<File>,
}

impl std::fmt::Debug for SshClientLog {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SshClientLog")
            .finish_non_exhaustive()
    }
}

impl SshClientLog {
    fn create() -> Result<Self, SshSpawnError> {
        let directory = tempfile::tempdir().map_err(|_| SshSpawnError::BackendUnavailable)?;
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .map_err(|_| SshSpawnError::BackendUnavailable)?;
        let path = directory.path().join("client-log");
        nix::unistd::mkfifo(
            &path,
            nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
        )
        .map_err(|_| SshSpawnError::BackendUnavailable)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
            .map_err(|_| SshSpawnError::BackendUnavailable)?;
        let mut options = fs::OpenOptions::new();
        options
            .read(true)
            .write(true)
            .custom_flags(nix::libc::O_NONBLOCK | nix::libc::O_CLOEXEC | nix::libc::O_NOFOLLOW);
        let file = options
            .open(&path)
            .map_err(|_| SshSpawnError::BackendUnavailable)?;
        let reader = AsyncFd::new(file).map_err(|_| SshSpawnError::BackendUnavailable)?;
        Ok(Self {
            _directory: directory,
            path,
            reader,
        })
    }

    #[allow(dead_code, reason = "the SSH lifecycle supervisor is added in Task 4")]
    pub(crate) async fn read(&self, buffer: &mut [u8]) -> std::io::Result<usize> {
        loop {
            let mut ready = self.reader.readable().await?;
            match ready.try_io(|inner| {
                let mut file = inner.get_ref();
                std::io::Read::read(&mut file, buffer)
            }) {
                Ok(result) => return result,
                Err(_) => continue,
            }
        }
    }
}

#[allow(dead_code, reason = "the SSH lifecycle supervisor is added in Task 4")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SshDiagnosticClass {
    Authenticated,
    UnknownHostKey,
    HostKeyMismatch,
    ConnectionFailed,
    AuthenticationFailed,
    GenericFailure,
}

#[allow(dead_code, reason = "the SSH lifecycle supervisor is added in Task 4")]
pub(crate) struct SshDiagnosticClassifier {
    expected_host: String,
    bytes: Vec<u8>,
    line_count: usize,
    current_line_bytes: usize,
    line_open: bool,
    invalid: bool,
}

impl std::fmt::Debug for SshDiagnosticClassifier {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SshDiagnosticClassifier")
            .field("accepted_bytes", &self.bytes.len())
            .field("invalid", &self.invalid)
            .finish()
    }
}

#[allow(dead_code, reason = "the SSH lifecycle supervisor is added in Task 4")]
impl SshDiagnosticClassifier {
    pub(crate) fn new(expected_host: &str) -> Self {
        Self {
            expected_host: expected_host.to_owned(),
            bytes: Vec::new(),
            line_count: 0,
            current_line_bytes: 0,
            line_open: false,
            invalid: false,
        }
    }

    pub(crate) fn push(&mut self, chunk: &[u8]) {
        if self.invalid
            || self
                .bytes
                .len()
                .checked_add(chunk.len())
                .is_none_or(|size| size > MAX_SSH_DIAGNOSTIC_BYTES)
        {
            self.invalid = true;
            self.bytes.clear();
            return;
        }
        for byte in chunk {
            if *byte == b'\n' {
                if !self.line_open {
                    self.line_count += 1;
                }
                self.current_line_bytes = 0;
                self.line_open = false;
                if self.line_count > MAX_SSH_DIAGNOSTIC_LINES {
                    self.invalid = true;
                    self.bytes.clear();
                    return;
                }
            } else {
                if !self.line_open {
                    self.line_count += 1;
                    self.line_open = true;
                }
                self.current_line_bytes += 1;
                if self.line_count > MAX_SSH_DIAGNOSTIC_LINES
                    || self.current_line_bytes > MAX_SSH_DIAGNOSTIC_LINE_BYTES
                {
                    self.invalid = true;
                    self.bytes.clear();
                    return;
                }
            }
        }
        self.bytes.extend_from_slice(chunk);
    }

    pub(crate) fn finish(self) -> SshDiagnosticClass {
        self.classification()
            .unwrap_or(SshDiagnosticClass::GenericFailure)
    }

    pub(crate) fn classification(&self) -> Option<SshDiagnosticClass> {
        if self.invalid {
            return Some(SshDiagnosticClass::GenericFailure);
        }
        let diagnostics = match std::str::from_utf8(&self.bytes) {
            Ok(diagnostics) => diagnostics,
            Err(error) if error.error_len().is_none() => return None,
            Err(_) => return Some(SshDiagnosticClass::GenericFailure),
        };
        classify_diagnostics(diagnostics, &self.expected_host)
    }
}

#[allow(dead_code, reason = "the SSH lifecycle supervisor is added in Task 4")]
fn classify_diagnostics(diagnostics: &str, expected_host: &str) -> Option<SshDiagnosticClass> {
    if diagnostics.contains("REMOTE HOST IDENTIFICATION HAS CHANGED!")
        || diagnostics.contains("Offending ") && diagnostics.contains(" key in ")
    {
        Some(SshDiagnosticClass::HostKeyMismatch)
    } else if diagnostics.contains("No ED25519 host key is known for ")
        || diagnostics.contains("No ECDSA host key is known for ")
        || diagnostics.contains("No RSA host key is known for ")
        || diagnostics.contains("Host key verification failed.")
    {
        Some(SshDiagnosticClass::UnknownHostKey)
    } else if diagnostics.split_inclusive('\n').any(|line| {
        let line = line.strip_suffix('\n').unwrap_or_default();
        let line = line.strip_suffix('\r').unwrap_or(line);
        let Some(authority) = line
            .strip_prefix("Authenticated to ")
            .and_then(|line| line.strip_suffix(" using \"publickey\"."))
        else {
            return false;
        };
        authority == expected_host
            || authority
                .strip_prefix(expected_host)
                .is_some_and(|suffix| suffix.starts_with(" ([") && suffix.ends_with(')'))
    }) {
        Some(SshDiagnosticClass::Authenticated)
    } else if diagnostics.contains("Permission denied (publickey")
        || diagnostics.contains("No more authentication methods to try.")
    {
        Some(SshDiagnosticClass::AuthenticationFailed)
    } else if diagnostics.contains("ssh: connect to host ")
        || diagnostics.contains("Could not resolve hostname ")
        || diagnostics.contains("Connection closed by ")
        || diagnostics.contains("Connection reset by ")
        || diagnostics.contains("Connection timed out")
    {
        Some(SshDiagnosticClass::ConnectionFailed)
    } else {
        None
    }
}

#[allow(dead_code, reason = "the SSH lifecycle supervisor is added in Task 4")]
pub(crate) fn spawn(
    spec: SshSpawnSpec,
    size: crate::protocol::Resize,
) -> Result<crate::pty_backend::RunningSsh, SshSpawnError> {
    spec.prepared
        .recheck_before_spawn()
        .map_err(|_| SshSpawnError::MaterialChanged)?;
    crate::pty_backend::PtyProcessBackend::spawn_ssh(spec, size)
        .map_err(|_| SshSpawnError::BackendUnavailable)
}

#[derive(Clone, Default)]
pub struct PreparedSshTargets {
    targets: BTreeMap<String, PreparedSshTarget>,
}

impl std::fmt::Debug for PreparedSshTargets {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PreparedSshTargets")
            .field("count", &self.targets.len())
            .finish()
    }
}

impl PreparedSshTargets {
    pub fn get(&self, name: &str) -> Option<&PreparedSshTarget> {
        self.targets.get(name)
    }

    pub fn iter(&self) -> impl Iterator<Item = &PreparedSshTarget> {
        self.targets.values()
    }

    pub(crate) fn validate_for_targets(
        &self,
        targets: &[Target],
    ) -> Result<(), SshPreparationError> {
        let mut configured = targets.iter().filter_map(|target| match target {
            Target::Ssh(target) => Some(target),
            Target::Pty(_) => None,
        });
        let count = configured.clone().count();
        if count == self.targets.len()
            && configured.all(|target| {
                self.targets
                    .get(&target.name)
                    .is_some_and(|prepared| prepared.matches_target(target))
            })
        {
            Ok(())
        } else {
            Err(SshPreparationError::PreparedTargetSetMismatch)
        }
    }

    #[cfg(test)]
    pub(crate) fn from_test_names<const N: usize>(names: [&str; N]) -> Self {
        let snapshot = FileSnapshot {
            device: 0,
            inode: 0,
            uid: 0,
            mode: 0,
            size: 0,
            modified_seconds: 0,
            modified_nanoseconds: 0,
            changed_seconds: 0,
            changed_nanoseconds: 0,
        };
        let targets = names
            .into_iter()
            .map(|name| {
                (
                    name.to_owned(),
                    PreparedSshTarget {
                        name: name.to_owned(),
                        host: "host.example".to_owned(),
                        port: 22,
                        user_policy: crate::config::SshUserPolicy::Fixed("operator".to_owned()),
                        read_only: false,
                        executable: "/test/ssh".into(),
                        executable_snapshot: snapshot.clone(),
                        known_hosts: "/test/known-hosts".into(),
                        known_hosts_snapshot: snapshot.clone(),
                        identity: "/test/identity".into(),
                        identity_snapshot: snapshot.clone(),
                    },
                )
            })
            .collect();
        Self { targets }
    }
}

pub async fn prepare(targets: &[Target]) -> Result<PreparedSshTargets, SshPreparationError> {
    prepare_with_probe(targets, |executable: PathBuf| async move {
        probe_capabilities(&executable).await
    })
    .await
}

pub async fn prepare_with_probe<P, F>(
    targets: &[Target],
    probe: P,
) -> Result<PreparedSshTargets, SshPreparationError>
where
    P: Fn(PathBuf) -> F,
    F: Future<Output = Result<(), SshPreparationError>>,
{
    let mut prepared = BTreeMap::new();
    for target in targets {
        let Target::Ssh(target) = target else {
            continue;
        };
        let target = prepare_target_with_probe(target, &probe).await?;
        prepared.insert(target.name.clone(), target);
    }
    Ok(PreparedSshTargets { targets: prepared })
}

async fn prepare_target_with_probe<P, F>(
    target: &SshTarget,
    probe: P,
) -> Result<PreparedSshTarget, SshPreparationError>
where
    P: Fn(PathBuf) -> F,
    F: Future<Output = Result<(), SshPreparationError>>,
{
    let (_, executable_snapshot) = read_file(
        &target.ssh_executable,
        MaterialKind::Executable,
        MAX_SSH_EXECUTABLE_BYTES,
    )?;
    let (known_hosts, known_hosts_snapshot) = read_file(
        &target.known_hosts,
        MaterialKind::KnownHosts,
        MAX_KNOWN_HOSTS_BYTES,
    )?;
    validate_known_hosts(&known_hosts)?;
    let (identity, identity_snapshot) = read_file(
        &target.identity_file,
        MaterialKind::Identity,
        MAX_IDENTITY_BYTES,
    )?;
    validate_identity(&identity)?;
    let prepared = PreparedSshTarget {
        name: target.name.clone(),
        host: target.host.clone(),
        port: target.port,
        user_policy: target.user_policy.clone(),
        read_only: target.read_only,
        executable: target.ssh_executable.clone(),
        executable_snapshot,
        known_hosts: target.known_hosts.clone(),
        known_hosts_snapshot,
        identity: target.identity_file.clone(),
        identity_snapshot,
    };
    prepared.recheck_before_spawn()?;
    probe(target.ssh_executable.clone()).await?;
    prepared.recheck_before_spawn()?;
    Ok(prepared)
}

pub async fn probe_capabilities(executable: &Path) -> Result<(), SshPreparationError> {
    let argv = capability_probe_argv();
    let mut command = Command::new(executable);
    command
        .args(argv)
        .env_clear()
        .env("LC_ALL", "C")
        .env("LANG", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let mut child = command
        .spawn()
        .map_err(|_| SshPreparationError::CapabilityUnsupported)?;
    let Some(stdout) = child.stdout.take() else {
        terminate_and_reap(&mut child).await;
        return Err(SshPreparationError::CapabilityUnsupported);
    };
    let Some(stderr) = child.stderr.take() else {
        terminate_and_reap(&mut child).await;
        return Err(SshPreparationError::CapabilityUnsupported);
    };
    let completed = timeout(PROBE_TIMEOUT, async {
        let stdout_read = async {
            let mut bytes = Vec::new();
            stdout
                .take(MAX_PROBE_OUTPUT_BYTES + 1)
                .read_to_end(&mut bytes)
                .await
                .map(|_| bytes)
        };
        let stderr_read = async {
            let mut bytes = Vec::new();
            stderr
                .take(MAX_PROBE_OUTPUT_BYTES + 1)
                .read_to_end(&mut bytes)
                .await
                .map(|_| bytes)
        };
        let (status, stdout, stderr) = tokio::join!(child.wait(), stdout_read, stderr_read);
        (status, stdout, stderr)
    })
    .await;
    let completed = match completed {
        Ok(completed) => completed,
        Err(_) => {
            terminate_and_reap(&mut child).await;
            return Err(SshPreparationError::CapabilityUnsupported);
        }
    };
    let (status, stdout, stderr) = completed;
    let status = match status {
        Ok(status) => status,
        Err(_) => {
            terminate_and_reap(&mut child).await;
            return Err(SshPreparationError::CapabilityUnsupported);
        }
    };
    let stdout = stdout.map_err(|_| SshPreparationError::CapabilityUnsupported)?;
    let stderr = stderr.map_err(|_| SshPreparationError::CapabilityUnsupported)?;
    if stdout.len() as u64 > MAX_PROBE_OUTPUT_BYTES || stderr.len() as u64 > MAX_PROBE_OUTPUT_BYTES
    {
        terminate_and_reap(&mut child).await;
        return Err(SshPreparationError::CapabilityUnsupported);
    }
    if !status.success() {
        return Err(SshPreparationError::CapabilityUnsupported);
    }
    let output =
        std::str::from_utf8(&stdout).map_err(|_| SshPreparationError::CapabilityUnsupported)?;
    let normalized = output.to_ascii_lowercase();
    let values = parse_probe_output(&normalized)?;
    let required_values = [
        ("batchmode", &["yes", "true"][..]),
        ("clearallforwardings", &["yes", "true"][..]),
        ("identitiesonly", &["yes", "true"][..]),
        ("identityagent", &["none"][..]),
        ("passwordauthentication", &["no", "false"][..]),
        ("kbdinteractiveauthentication", &["no", "false"][..]),
        ("updatehostkeys", &["no", "false"][..]),
        ("checkhostip", &["yes", "true"][..]),
        ("identityfile", &["/dev/null"][..]),
        ("addkeystoagent", &["no", "false"][..]),
        ("preferredauthentications", &["publickey"][..]),
        ("pubkeyauthentication", &["yes", "true"][..]),
        ("hostbasedauthentication", &["no", "false"][..]),
        ("gssapiauthentication", &["no", "false"][..]),
        ("forwardagent", &["no", "false"][..]),
        ("forwardx11", &["no", "false"][..]),
        ("forwardx11trusted", &["no", "false"][..]),
        ("permitlocalcommand", &["no", "false"][..]),
        ("enableescapecommandline", &["no", "false"][..]),
        ("escapechar", &["none"][..]),
        ("canonicalizehostname", &["no", "false"][..]),
        ("requesttty", &["force"][..]),
        ("stricthostkeychecking", &["yes", "true"][..]),
        ("userknownhostsfile", &["/dev/null"][..]),
        ("globalknownhostsfile", &["/dev/null"][..]),
    ];
    if required_values.iter().any(|(key, allowed)| {
        values
            .get(*key)
            .is_none_or(|value| !allowed.contains(value))
    }) || values.contains_key("proxycommand")
        || values.contains_key("proxyjump")
    {
        return Err(SshPreparationError::CapabilityUnsupported);
    }
    Ok(())
}

async fn terminate_and_reap(child: &mut tokio::process::Child) {
    let _ = child.start_kill();
    let _ = child.wait().await;
}

fn parse_probe_output(output: &str) -> Result<BTreeMap<&str, &str>, SshPreparationError> {
    let mut values = BTreeMap::new();
    for line in output.lines() {
        let (key, value) = line
            .split_once(char::is_whitespace)
            .ok_or(SshPreparationError::CapabilityUnsupported)?;
        if value.trim().is_empty() || values.insert(key, value.trim()).is_some() {
            return Err(SshPreparationError::CapabilityUnsupported);
        }
    }
    Ok(values)
}

#[derive(Clone, Copy)]
enum MaterialKind {
    Executable,
    KnownHosts,
    Identity,
}

fn read_file(
    path: &Path,
    kind: MaterialKind,
    maximum: u64,
) -> Result<(Vec<u8>, FileSnapshot), SshPreparationError> {
    if !path.is_absolute() {
        return Err(kind.error());
    }
    let mut options = fs::OpenOptions::new();
    options
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC | nix::libc::O_NONBLOCK);
    let file = options.open(path).map_err(|_| kind.error())?;
    let metadata = file.metadata().map_err(|_| kind.error())?;
    validate_metadata(&metadata, kind, maximum)?;
    let snapshot = FileSnapshot::from_metadata(&metadata);
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    File::take(file.try_clone().map_err(|_| kind.error())?, maximum + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| kind.error())?;
    let after = file.metadata().map_err(|_| kind.error())?;
    if FileSnapshot::from_metadata(&after) != snapshot
        || bytes.is_empty()
        || bytes.len() as u64 > maximum
    {
        return Err(kind.error());
    }
    Ok((bytes, snapshot))
}

fn validate_metadata(
    metadata: &fs::Metadata,
    kind: MaterialKind,
    maximum: u64,
) -> Result<(), SshPreparationError> {
    if !metadata.file_type().is_file() || metadata.len() == 0 || metadata.len() > maximum {
        return Err(kind.error());
    }
    let effective_uid = nix::unistd::geteuid().as_raw();
    let mode = metadata.mode();
    match kind {
        MaterialKind::Executable => {
            if (metadata.uid() != 0 && metadata.uid() != effective_uid)
                || mode & 0o022 != 0
                || !executable_by_daemon(metadata, effective_uid)
            {
                return Err(kind.error());
            }
        }
        MaterialKind::KnownHosts => {
            if metadata.uid() != effective_uid || mode & 0o022 != 0 {
                return Err(kind.error());
            }
        }
        MaterialKind::Identity => {
            if metadata.uid() != effective_uid || mode & 0o077 != 0 {
                return Err(kind.error());
            }
        }
    }
    Ok(())
}

fn executable_by_daemon(metadata: &fs::Metadata, effective_uid: u32) -> bool {
    let mode = metadata.mode();
    if metadata.uid() == effective_uid {
        return mode & 0o100 != 0;
    }
    if mode & 0o001 != 0 {
        return true;
    }
    if mode & 0o010 == 0 {
        return false;
    }
    let effective_gid = nix::unistd::getegid().as_raw();
    metadata.gid() == effective_gid
}

impl MaterialKind {
    fn error(self) -> SshPreparationError {
        match self {
            Self::Executable => SshPreparationError::ExecutableUnsafe,
            Self::KnownHosts => SshPreparationError::KnownHostsUnsafe,
            Self::Identity => SshPreparationError::IdentityUnsafe,
        }
    }
}

fn validate_known_hosts(bytes: &[u8]) -> Result<(), SshPreparationError> {
    if !bytes.ends_with(b"\n") || bytes.contains(&0) {
        return Err(SshPreparationError::KnownHostsUnsafe);
    }
    Ok(())
}

fn validate_identity(bytes: &[u8]) -> Result<(), SshPreparationError> {
    const BEGIN: &[u8] = b"-----BEGIN OPENSSH PRIVATE KEY-----\n";
    const END: &[u8] = b"-----END OPENSSH PRIVATE KEY-----\n";
    if !bytes.ends_with(b"\n") || bytes.contains(&0) {
        return Err(SshPreparationError::IdentityUnsafe);
    }
    let encoded = bytes
        .strip_prefix(BEGIN)
        .and_then(|bytes| bytes.strip_suffix(END))
        .ok_or(SshPreparationError::IdentityUnsafe)?;
    if encoded.is_empty() || encoded.contains(&b'-') {
        return Err(SshPreparationError::IdentityUnsafe);
    }
    let encoded = encoded
        .split(|byte| *byte == b'\n')
        .flat_map(|line| line.iter().copied())
        .collect::<Vec<_>>();
    let decoded = STANDARD
        .decode(encoded)
        .map_err(|_| SshPreparationError::IdentityUnsafe)?;
    let mut remaining = decoded
        .strip_prefix(b"openssh-key-v1\0")
        .ok_or(SshPreparationError::IdentityUnsafe)?;
    let cipher = take_ssh_string(&mut remaining)?;
    let kdf = take_ssh_string(&mut remaining)?;
    let kdf_options = take_ssh_string(&mut remaining)?;
    if cipher != b"none" || kdf != b"none" || !kdf_options.is_empty() {
        return Err(SshPreparationError::IdentityUnsafe);
    }
    if take_u32(&mut remaining)? != 1 {
        return Err(SshPreparationError::IdentityUnsafe);
    }
    let mut public_blob = take_ssh_string(&mut remaining)?;
    let private_block = take_ssh_string(&mut remaining)?;
    if private_block.len() % 8 != 0 {
        return Err(SshPreparationError::IdentityUnsafe);
    }
    let mut private_block = private_block;
    if !remaining.is_empty() {
        return Err(SshPreparationError::IdentityUnsafe);
    }
    let public_key_type = take_ssh_string(&mut public_blob)?;
    let outer_public = take_ssh_string(&mut public_blob)?;
    if public_key_type != b"ssh-ed25519" || outer_public.len() != 32 || !public_blob.is_empty() {
        return Err(SshPreparationError::IdentityUnsafe);
    }
    let first_check = take_u32(&mut private_block)?;
    let second_check = take_u32(&mut private_block)?;
    let key_type = take_ssh_string(&mut private_block)?;
    let inner_public = take_ssh_string(&mut private_block)?;
    let private_key = take_ssh_string(&mut private_block)?;
    let comment = take_ssh_string(&mut private_block)?;
    // This is bounded envelope validation, not an independent credential
    // implementation. OpenSSH derives and verifies the Ed25519 key material.
    if first_check != second_check
        || key_type != b"ssh-ed25519"
        || inner_public.len() != 32
        || private_key.len() != 64
        || private_key.get(32..) != Some(inner_public)
        || inner_public != outer_public
        || comment.len() > MAX_IDENTITY_COMMENT_BYTES
        || !canonical_padding(private_block)
    {
        return Err(SshPreparationError::IdentityUnsafe);
    }
    Ok(())
}

fn canonical_padding(bytes: &[u8]) -> bool {
    !bytes.is_empty()
        && bytes.len() <= 8
        && bytes
            .iter()
            .copied()
            .enumerate()
            .all(|(index, byte)| byte == (index + 1) as u8)
}

fn take_ssh_string<'a>(remaining: &mut &'a [u8]) -> Result<&'a [u8], SshPreparationError> {
    let length = remaining
        .get(..4)
        .and_then(|bytes| bytes.try_into().ok())
        .map(u32::from_be_bytes)
        .ok_or(SshPreparationError::IdentityUnsafe)? as usize;
    let end = checked_string_end(4, length).ok_or(SshPreparationError::IdentityUnsafe)?;
    let value = remaining
        .get(4..end)
        .ok_or(SshPreparationError::IdentityUnsafe)?;
    *remaining = remaining
        .get(end..)
        .ok_or(SshPreparationError::IdentityUnsafe)?;
    Ok(value)
}

fn checked_string_end(start: usize, length: usize) -> Option<usize> {
    start.checked_add(length)
}

fn take_u32(remaining: &mut &[u8]) -> Result<u32, SshPreparationError> {
    let value = remaining
        .get(..4)
        .and_then(|bytes| bytes.try_into().ok())
        .map(u32::from_be_bytes)
        .ok_or(SshPreparationError::IdentityUnsafe)?;
    *remaining = remaining
        .get(4..)
        .ok_or(SshPreparationError::IdentityUnsafe)?;
    Ok(value)
}

fn recheck(path: &Path, expected: &FileSnapshot) -> Result<(), SshPreparationError> {
    let mut options = fs::OpenOptions::new();
    options
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC | nix::libc::O_NONBLOCK);
    let file = options
        .open(path)
        .map_err(|_| SshPreparationError::MaterialChanged)?;
    let actual = file
        .metadata()
        .map(|metadata| FileSnapshot::from_metadata(&metadata))
        .map_err(|_| SshPreparationError::MaterialChanged)?;
    if &actual != expected {
        return Err(SshPreparationError::MaterialChanged);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{
        ffi::OsString,
        fs,
        os::unix::fs::{PermissionsExt, symlink},
        path::{Path, PathBuf},
        sync::{Arc, Mutex},
    };

    use base64::{Engine, engine::general_purpose::STANDARD};
    use tempfile::TempDir;

    use crate::config::{SshTarget, SshUserPolicy, Target};

    use super::{
        SshPreparationError, prepare_target_with_probe, prepare_with_probe, probe_capabilities,
    };

    const KNOWN_HOST: &[u8] = b"host.example ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA==\n";
    static REAL_PROBE_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    struct Material {
        directory: TempDir,
        executable: PathBuf,
        known_hosts: PathBuf,
        identity: PathBuf,
    }

    impl Material {
        fn new() -> Self {
            let directory = tempfile::tempdir().unwrap();
            let executable = directory.path().join("ssh");
            let known_hosts = directory.path().join("known_hosts");
            let identity = directory.path().join("identity");
            write(&executable, b"#!/bin/sh\nexit 0\n", 0o700);
            write(&known_hosts, KNOWN_HOST, 0o644);
            write(&identity, &unencrypted_identity(), 0o600);
            Self {
                directory,
                executable,
                known_hosts,
                identity,
            }
        }

        fn target(&self) -> SshTarget {
            SshTarget {
                name: "remote".into(),
                host: "host.example".into(),
                port: 22,
                ssh_executable: self.executable.clone(),
                identity_file: self.identity.clone(),
                known_hosts: self.known_hosts.clone(),
                user_policy: SshUserPolicy::Fixed("operator".into()),
                read_only: false,
            }
        }
    }

    fn write(path: &Path, bytes: &[u8], mode: u32) {
        fs::write(path, bytes).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
    }

    fn wrong_owner_path(directory: &Path, name: &str) -> PathBuf {
        let effective_uid = nix::unistd::geteuid();
        if effective_uid.as_raw() != 0 {
            let system_file = PathBuf::from("/usr/bin/ssh");
            use std::os::unix::fs::MetadataExt;
            assert_ne!(
                fs::metadata(&system_file).unwrap().uid(),
                effective_uid.as_raw()
            );
            return system_file;
        }
        let path = directory.join(name);
        write(&path, b"wrong-owner\n", 0o600);
        nix::unistd::chown(&path, Some(nix::unistd::Uid::from_raw(1)), None).unwrap();
        path
    }

    fn string(output: &mut Vec<u8>, value: &[u8]) {
        output.extend_from_slice(&(value.len() as u32).to_be_bytes());
        output.extend_from_slice(value);
    }

    fn pem_identity(binary: &[u8]) -> Vec<u8> {
        let encoded = STANDARD.encode(binary);
        format!(
            "-----BEGIN OPENSSH PRIVATE KEY-----\n{encoded}\n-----END OPENSSH PRIVATE KEY-----\n"
        )
        .into_bytes()
    }

    fn unencrypted_identity_with_padding(padding: &[u8]) -> Vec<u8> {
        let public = [0x42; 32];
        let mut binary = b"openssh-key-v1\0".to_vec();
        string(&mut binary, b"none");
        string(&mut binary, b"none");
        string(&mut binary, b"");
        binary.extend_from_slice(&1u32.to_be_bytes());
        let mut public_blob = Vec::new();
        string(&mut public_blob, b"ssh-ed25519");
        string(&mut public_blob, &public);
        string(&mut binary, &public_blob);
        let mut private = 0x1234_5678u32.to_be_bytes().to_vec();
        private.extend_from_slice(&0x1234_5678u32.to_be_bytes());
        string(&mut private, b"ssh-ed25519");
        string(&mut private, &public);
        let mut private_key = [0x24; 64];
        private_key[32..].copy_from_slice(&public);
        string(&mut private, &private_key);
        string(&mut private, b"synthetic-non-secret");
        private.extend_from_slice(padding);
        string(&mut binary, &private);
        pem_identity(&binary)
    }

    fn unencrypted_identity() -> Vec<u8> {
        unencrypted_identity_with_padding(&[1])
    }

    fn incomplete_identity() -> Vec<u8> {
        let mut binary = b"openssh-key-v1\0".to_vec();
        for value in [b"none".as_slice(), b"none", b""] {
            binary.extend_from_slice(&(value.len() as u32).to_be_bytes());
            binary.extend_from_slice(value);
        }
        format!(
            "-----BEGIN OPENSSH PRIVATE KEY-----\n{}\n-----END OPENSSH PRIVATE KEY-----\n",
            STANDARD.encode(binary)
        )
        .into_bytes()
    }

    async fn accept_probe(_: PathBuf) -> Result<(), SshPreparationError> {
        Ok(())
    }

    fn strict_probe_output() -> &'static str {
        "stricthostkeychecking true\n\
userknownhostsfile /dev/null\n\
globalknownhostsfile /dev/null\n\
updatehostkeys false\n\
checkhostip yes\n\
batchmode yes\n\
identitiesonly yes\n\
identityfile /dev/null\n\
identityagent none\n\
addkeystoagent false\n\
preferredauthentications publickey\n\
pubkeyauthentication true\n\
passwordauthentication no\n\
kbdinteractiveauthentication no\n\
hostbasedauthentication no\n\
gssapiauthentication no\n\
forwardagent no\n\
forwardx11 no\n\
forwardx11trusted no\n\
clearallforwardings yes\n\
permitlocalcommand no\n\
enableescapecommandline no\n\
escapechar none\n\
canonicalizehostname false\n\
requesttty force\n"
    }

    #[tokio::test]
    async fn ssh_executable_rejects_relative_symlink_special_nonexecutable_and_writable_files() {
        let material = Material::new();
        let symlink_path = material.directory.path().join("ssh-link");
        symlink(&material.executable, &symlink_path).unwrap();
        let special = material.directory.path().join("ssh-special");
        nix::unistd::mkfifo(&special, nix::sys::stat::Mode::S_IRUSR).unwrap();
        let relative = PathBuf::from("relative-ssh");

        for (path, mode) in [
            (relative, None),
            (symlink_path, None),
            (special, None),
            (material.executable.clone(), Some(0o600)),
            (material.executable.clone(), Some(0o722)),
        ] {
            if let Some(mode) = mode {
                fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
            }
            let mut target = material.target();
            target.ssh_executable = path;
            let error = prepare_target_with_probe(&target, accept_probe)
                .await
                .unwrap_err();
            assert_eq!(error, SshPreparationError::ExecutableUnsafe);
            assert!(
                !error
                    .to_string()
                    .contains(material.directory.path().to_str().unwrap())
            );
        }
    }

    #[tokio::test]
    async fn known_hosts_rejects_relative_symlink_directory_special_wrong_owner_unsafe_empty_oversize_and_incomplete_data()
     {
        let material = Material::new();
        let symlink_path = material.directory.path().join("known-hosts-link");
        symlink(&material.known_hosts, &symlink_path).unwrap();
        let special = material.directory.path().join("known-hosts-special");
        nix::unistd::mkfifo(&special, nix::sys::stat::Mode::S_IRUSR).unwrap();
        let cases = [
            (PathBuf::from("relative-known-hosts"), None, None),
            (symlink_path, None, None),
            (material.directory.path().to_path_buf(), None, None),
            (special, None, None),
            (material.known_hosts.clone(), Some(KNOWN_HOST), Some(0o666)),
            (material.known_hosts.clone(), Some(b""), Some(0o600)),
            (
                material.known_hosts.clone(),
                Some(&vec![b'a'; super::MAX_KNOWN_HOSTS_BYTES as usize + 1]),
                Some(0o600),
            ),
            (
                material.known_hosts.clone(),
                Some(b"host ssh-ed25519 AAAA"),
                Some(0o600),
            ),
            (
                material.known_hosts.clone(),
                Some(b"host\0 ssh-ed25519 AAAA\n"),
                Some(0o600),
            ),
        ];
        for (path, contents, mode) in cases {
            if let Some(contents) = contents {
                write(&path, contents, mode.unwrap());
            }
            let mut target = material.target();
            target.known_hosts = path;
            assert_eq!(
                prepare_target_with_probe(&target, accept_probe)
                    .await
                    .unwrap_err(),
                SshPreparationError::KnownHostsUnsafe
            );
        }

        let mut target = material.target();
        target.known_hosts = wrong_owner_path(material.directory.path(), "wrong-owner-known-hosts");
        assert_eq!(
            prepare_target_with_probe(&target, accept_probe)
                .await
                .unwrap_err(),
            SshPreparationError::KnownHostsUnsafe
        );
    }

    #[tokio::test]
    async fn identity_rejects_relative_symlink_directory_special_wrong_owner_unsafe_empty_oversize_encrypted_and_trailing_data()
     {
        let material = Material::new();
        let symlink_path = material.directory.path().join("identity-link");
        symlink(&material.identity, &symlink_path).unwrap();
        let special = material.directory.path().join("identity-special");
        nix::unistd::mkfifo(&special, nix::sys::stat::Mode::S_IRUSR).unwrap();
        let mut encrypted_binary = b"openssh-key-v1\0".to_vec();
        for value in [b"aes256-ctr".as_slice(), b"bcrypt", b"salt"] {
            encrypted_binary.extend_from_slice(&(value.len() as u32).to_be_bytes());
            encrypted_binary.extend_from_slice(value);
        }
        let encrypted = format!(
            "-----BEGIN OPENSSH PRIVATE KEY-----\n{}\n-----END OPENSSH PRIVATE KEY-----\n",
            STANDARD.encode(encrypted_binary)
        );
        let mut trailing = unencrypted_identity();
        trailing.extend_from_slice(b"trailing\n");
        let cases = [
            (PathBuf::from("relative-identity"), None, None),
            (symlink_path, None, None),
            (material.directory.path().to_path_buf(), None, None),
            (special, None, None),
            (
                material.identity.clone(),
                Some(unencrypted_identity()),
                Some(0o640),
            ),
            (material.identity.clone(), Some(Vec::new()), Some(0o600)),
            (
                material.identity.clone(),
                Some(vec![b'a'; super::MAX_IDENTITY_BYTES as usize + 1]),
                Some(0o600),
            ),
            (
                material.identity.clone(),
                Some(encrypted.into_bytes()),
                Some(0o600),
            ),
            (
                material.identity.clone(),
                Some(incomplete_identity()),
                Some(0o600),
            ),
            (material.identity.clone(), Some(trailing), Some(0o600)),
        ];
        for (path, contents, mode) in cases {
            if let Some(contents) = contents {
                write(&path, &contents, mode.unwrap());
            }
            let mut target = material.target();
            target.identity_file = path;
            assert_eq!(
                prepare_target_with_probe(&target, accept_probe)
                    .await
                    .unwrap_err(),
                SshPreparationError::IdentityUnsafe
            );
        }

        let mut target = material.target();
        target.identity_file = wrong_owner_path(material.directory.path(), "wrong-owner-identity");
        assert_eq!(
            prepare_target_with_probe(&target, accept_probe)
                .await
                .unwrap_err(),
            SshPreparationError::IdentityUnsafe
        );
    }

    #[test]
    fn identity_parser_rejects_malformed_ed25519_structure() {
        #[derive(Clone)]
        struct IdentityParts {
            outer_type: Vec<u8>,
            outer_public: Vec<u8>,
            checks: (u32, u32),
            inner_type: Vec<u8>,
            inner_public: Vec<u8>,
            private_key: Vec<u8>,
            comment: Option<Vec<u8>>,
            padding: Vec<u8>,
            outer_trailing: Vec<u8>,
        }

        fn identity(parts: &IdentityParts) -> Vec<u8> {
            let mut binary = b"openssh-key-v1\0".to_vec();
            string(&mut binary, b"none");
            string(&mut binary, b"none");
            string(&mut binary, b"");
            binary.extend_from_slice(&1u32.to_be_bytes());
            let mut public_blob = Vec::new();
            string(&mut public_blob, &parts.outer_type);
            string(&mut public_blob, &parts.outer_public);
            string(&mut binary, &public_blob);
            let mut private = parts.checks.0.to_be_bytes().to_vec();
            private.extend_from_slice(&parts.checks.1.to_be_bytes());
            string(&mut private, &parts.inner_type);
            string(&mut private, &parts.inner_public);
            string(&mut private, &parts.private_key);
            if let Some(comment) = &parts.comment {
                string(&mut private, comment);
            }
            private.extend_from_slice(&parts.padding);
            string(&mut binary, &private);
            binary.extend_from_slice(&parts.outer_trailing);
            pem_identity(&binary)
        }

        let public = vec![0x42; 32];
        let mut private_key = vec![0x24; 64];
        private_key[32..].copy_from_slice(&public);
        let valid = IdentityParts {
            outer_type: b"ssh-ed25519".to_vec(),
            outer_public: public.clone(),
            checks: (7, 7),
            inner_type: b"ssh-ed25519".to_vec(),
            inner_public: public,
            private_key,
            comment: Some(b"comment".to_vec()),
            padding: vec![1],
            outer_trailing: Vec::new(),
        };
        let malformed = [
            {
                let mut parts = valid.clone();
                parts.outer_type = b"ssh-rsa".to_vec();
                identity(&parts)
            },
            {
                let mut parts = valid.clone();
                parts.outer_public.pop();
                identity(&parts)
            },
            {
                let mut parts = valid.clone();
                parts.checks.1 += 1;
                identity(&parts)
            },
            {
                let mut parts = valid.clone();
                parts.inner_type = b"ssh-rsa".to_vec();
                identity(&parts)
            },
            {
                let mut parts = valid.clone();
                parts.inner_public.fill(0x43);
                identity(&parts)
            },
            {
                let mut parts = valid.clone();
                parts.private_key.pop();
                identity(&parts)
            },
            {
                let mut parts = valid.clone();
                parts.private_key[32..].fill(0x43);
                identity(&parts)
            },
            {
                let mut parts = valid.clone();
                parts.comment = None;
                identity(&parts)
            },
            {
                let mut parts = valid.clone();
                parts.comment = Some(vec![b'c'; super::MAX_IDENTITY_COMMENT_BYTES + 1]);
                identity(&parts)
            },
            {
                let mut parts = valid.clone();
                parts.padding.clear();
                identity(&parts)
            },
            {
                let mut parts = valid.clone();
                parts.padding = vec![1, 3];
                identity(&parts)
            },
            {
                let mut parts = valid;
                parts.outer_trailing = b"trailing".to_vec();
                identity(&parts)
            },
        ];
        for bytes in malformed {
            assert_eq!(
                super::validate_identity(&bytes).unwrap_err(),
                SshPreparationError::IdentityUnsafe
            );
        }
        assert!(super::validate_identity(&unencrypted_identity()).is_ok());
    }

    #[tokio::test]
    async fn ssh_material_paths_are_rechecked_before_spawn() {
        let material = Material::new();
        let prepared = prepare_target_with_probe(&material.target(), accept_probe)
            .await
            .unwrap();
        assert!(prepared.recheck_before_spawn().is_ok());

        let replacement = material.directory.path().join("replacement");
        write(&replacement, KNOWN_HOST, 0o644);
        fs::rename(&replacement, &material.known_hosts).unwrap();
        assert_eq!(
            prepared.recheck_before_spawn().unwrap_err(),
            SshPreparationError::MaterialChanged
        );

        let material = Material::new();
        let known_hosts = material.known_hosts.clone();
        let error = prepare_target_with_probe(&material.target(), move |_| {
            let replacement = known_hosts.with_extension("replacement");
            write(&replacement, KNOWN_HOST, 0o644);
            fs::rename(replacement, &known_hosts).unwrap();
            std::future::ready(Ok(()))
        })
        .await
        .unwrap_err();
        assert_eq!(error, SshPreparationError::MaterialChanged);
    }

    #[tokio::test]
    async fn ssh_capability_probe_uses_literal_executable_fixed_argv_and_cleared_environment() {
        let _probe_guard = REAL_PROBE_TEST_LOCK.lock().await;
        let material = Material::new();
        let record_path = material.directory.path().join("probe-record");
        let script = format!(
            "#!/bin/sh\n{{ printf '%s\\n' \"$@\"; env; }} > '{}'\nprintf '%s' '{}'\n",
            record_path.display(),
            strict_probe_output()
        );
        write(&material.executable, script.as_bytes(), 0o700);
        probe_capabilities(&material.executable).await.unwrap();

        let record = fs::read_to_string(record_path).unwrap();
        let lines = record.lines().map(OsString::from).collect::<Vec<_>>();
        let expected_argv = super::capability_probe_argv();
        assert_eq!(
            &lines[..expected_argv.len()],
            expected_argv.iter().map(OsString::from).collect::<Vec<_>>()
        );
        assert!(record.contains("LC_ALL=C"));
        assert!(record.contains("LANG=C"));
        assert!(!record.lines().any(|line| line.starts_with("PATH=")));
    }

    #[tokio::test]
    async fn capability_probe_covers_and_validates_complete_strict_runtime_vocabulary() {
        let _probe_guard = REAL_PROBE_TEST_LOCK.lock().await;
        let expected = [
            "StrictHostKeyChecking=yes",
            "UserKnownHostsFile=/dev/null",
            "GlobalKnownHostsFile=/dev/null",
            "UpdateHostKeys=no",
            "CheckHostIP=yes",
            "BatchMode=yes",
            "IdentitiesOnly=yes",
            "IdentityFile=/dev/null",
            "IdentityAgent=none",
            "AddKeysToAgent=no",
            "PreferredAuthentications=publickey",
            "PubkeyAuthentication=yes",
            "PasswordAuthentication=no",
            "KbdInteractiveAuthentication=no",
            "ChallengeResponseAuthentication=no",
            "HostbasedAuthentication=no",
            "GSSAPIAuthentication=no",
            "ForwardAgent=no",
            "ForwardX11=no",
            "ForwardX11Trusted=no",
            "ClearAllForwardings=yes",
            "PermitLocalCommand=no",
            "ProxyCommand=none",
            "ProxyJump=none",
            "EnableEscapeCommandline=no",
            "EscapeChar=none",
            "CanonicalizeHostname=no",
            "RequestTTY=force",
        ];
        let argv = super::capability_probe_argv();
        assert_eq!(&argv[..5], ["-G", "-E", "/dev/null", "-F", "/dev/null"]);
        assert_eq!(
            &argv[argv.len() - 2..],
            ["--", "ttygate-capability.invalid"]
        );
        let option_argv = &argv[5..argv.len() - 2];
        assert_eq!(option_argv.len(), expected.len() * 2);
        for (index, expected) in expected.iter().enumerate() {
            assert_eq!(option_argv[index * 2], "-o");
            assert_eq!(option_argv[index * 2 + 1], *expected);
            assert_eq!(
                option_argv
                    .iter()
                    .filter(|argument| *argument == expected)
                    .count(),
                1
            );
        }

        let material = Material::new();
        for omitted in strict_probe_output().lines() {
            let bad_output = strict_probe_output()
                .lines()
                .filter(|line| *line != omitted)
                .collect::<Vec<_>>()
                .join("\n");
            let script = format!("#!/bin/sh\nprintf '%s\\n' '{bad_output}'\n");
            write(&material.executable, script.as_bytes(), 0o700);
            assert_eq!(
                probe_capabilities(&material.executable).await.unwrap_err(),
                SshPreparationError::CapabilityUnsupported,
                "probe accepted output missing {omitted}"
            );
        }
    }

    fn assert_process_absent_and_reaped(pid: i32) {
        let pid = nix::unistd::Pid::from_raw(pid);
        assert_eq!(
            nix::sys::signal::kill(pid, None).unwrap_err(),
            nix::errno::Errno::ESRCH
        );
        assert_eq!(
            nix::sys::wait::waitpid(pid, Some(nix::sys::wait::WaitPidFlag::WNOHANG)).unwrap_err(),
            nix::errno::Errno::ECHILD
        );
    }

    #[tokio::test]
    async fn capability_probe_timeout_kills_and_reaps_child() {
        let _probe_guard = REAL_PROBE_TEST_LOCK.lock().await;
        let material = Material::new();
        let pid_path = material.directory.path().join("hanging-probe.pid");
        let script = format!(
            "#!/bin/sh\nprintf '%s' \"$$\" > '{}'\nwhile :; do :; done\n",
            pid_path.display()
        );
        write(&material.executable, script.as_bytes(), 0o700);

        let started = tokio::time::Instant::now();
        assert_eq!(
            probe_capabilities(&material.executable).await.unwrap_err(),
            SshPreparationError::CapabilityUnsupported
        );
        assert!(started.elapsed() < std::time::Duration::from_secs(4));
        let pid = fs::read_to_string(pid_path)
            .unwrap()
            .parse::<i32>()
            .unwrap();
        assert_process_absent_and_reaped(pid);
    }

    #[tokio::test]
    async fn capability_probe_output_limit_kills_and_reaps_flooding_child() {
        let _probe_guard = REAL_PROBE_TEST_LOCK.lock().await;
        let material = Material::new();
        let pid_path = material.directory.path().join("flooding-probe.pid");
        let script = format!(
            "#!/bin/sh\nprintf '%s' \"$$\" > '{}'\ntrap '' PIPE\nwhile :; do printf 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'; printf 'yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy' >&2; done\n",
            pid_path.display()
        );
        write(&material.executable, script.as_bytes(), 0o700);

        let started = tokio::time::Instant::now();
        assert_eq!(
            probe_capabilities(&material.executable).await.unwrap_err(),
            SshPreparationError::CapabilityUnsupported
        );
        assert!(started.elapsed() < std::time::Duration::from_secs(4));
        let pid = fs::read_to_string(pid_path)
            .unwrap()
            .parse::<i32>()
            .unwrap();
        assert_process_absent_and_reaped(pid);
    }

    #[test]
    fn cipher_none_padding_requires_exact_aligned_openssh_block() {
        assert!(super::validate_identity(&unencrypted_identity_with_padding(&[1])).is_ok());
        for padding in [
            Vec::new(),
            vec![1, 2],
            (1u8..=9).collect::<Vec<_>>(),
            vec![2],
        ] {
            assert_eq!(
                super::validate_identity(&unencrypted_identity_with_padding(&padding)).unwrap_err(),
                SshPreparationError::IdentityUnsafe
            );
        }
    }

    #[test]
    fn ssh_string_maximal_length_prefix_uses_checked_bounds() {
        assert!(super::checked_string_end(usize::MAX, 1).is_none());
        let bytes = u32::MAX.to_be_bytes();
        let mut remaining = bytes.as_slice();
        assert_eq!(
            super::take_ssh_string(&mut remaining).unwrap_err(),
            SshPreparationError::IdentityUnsafe
        );
    }

    #[tokio::test]
    async fn capability_probe_rejects_duplicate_contradictory_and_unsafe_proxy_transcripts() {
        let _probe_guard = REAL_PROBE_TEST_LOCK.lock().await;
        let material = Material::new();
        for suffix in [
            "batchmode no\n",
            "proxycommand /tmp/unsafe\n",
            "proxyjump unsafe.example\n",
        ] {
            let output = format!("{}{suffix}", strict_probe_output());
            let script = format!("#!/bin/sh\nprintf '%s' '{output}'\n");
            write(&material.executable, script.as_bytes(), 0o700);
            assert_eq!(
                probe_capabilities(&material.executable).await.unwrap_err(),
                SshPreparationError::CapabilityUnsupported
            );
        }
    }

    #[tokio::test]
    async fn installed_openssh_accepts_required_capability_policy_when_available() {
        let _probe_guard = REAL_PROBE_TEST_LOCK.lock().await;
        let executable = Path::new("/usr/bin/ssh");
        match fs::metadata(executable) {
            Ok(metadata) if metadata.is_file() => probe_capabilities(executable).await.unwrap(),
            Ok(_) => panic!("supported /usr/bin/ssh path is not a regular file"),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                eprintln!("supported OpenSSH executable is unavailable; explicit skip")
            }
            Err(error) => panic!("could not inspect supported OpenSSH executable: {error}"),
        }
    }

    #[tokio::test]
    async fn production_configured_ssh_target_has_no_insecure_runtime_fallback() {
        let material = Material::new();
        let calls = Arc::new(Mutex::new(Vec::new()));
        let observed = Arc::clone(&calls);
        let target = Target::Ssh(material.target());
        let error = prepare_with_probe(&[target], move |path: PathBuf| {
            observed.lock().unwrap().push(path);
            std::future::ready(Err(SshPreparationError::CapabilityUnsupported))
        })
        .await
        .unwrap_err();
        assert_eq!(error, SshPreparationError::CapabilityUnsupported);
        assert_eq!(*calls.lock().unwrap(), [material.executable]);
    }

    async fn prepared_runtime_fixture(
        material: &Material,
    ) -> (SshTarget, super::PreparedSshTarget) {
        let target = material.target();
        let prepared = prepare_target_with_probe(&target, accept_probe)
            .await
            .unwrap();
        (target, prepared)
    }

    fn runtime_options(argv: &[OsString]) -> Vec<&str> {
        argv.windows(2)
            .filter(|pair| pair[0] == "-o")
            .map(|pair| pair[1].to_str().unwrap())
            .collect()
    }

    #[tokio::test]
    async fn ssh_argv_serializes_every_pinned_option_exactly_once() {
        let material = Material::new();
        let (_target, prepared) = prepared_runtime_fixture(&material).await;
        let spec = super::SshSpawnSpec::build(&prepared, "browser-user").unwrap();
        let argv = spec.argv();
        let options = runtime_options(argv);
        assert_eq!(options.len(), super::STRICT_SSH_PROBE_OPTIONS.len());
        for probe_option in super::STRICT_SSH_PROBE_OPTIONS {
            let key = probe_option.split_once('=').unwrap().0;
            assert_eq!(
                options
                    .iter()
                    .filter(|option| option.split_once('=').unwrap().0 == key)
                    .count(),
                1,
                "{key} was not serialized exactly once"
            );
        }
        assert_eq!(argv[0], "-vv");
        assert_eq!(argv[1], "-tt");
    }

    #[tokio::test]
    async fn ssh_spawn_contract_uses_no_shell_and_only_the_literal_executable() {
        let material = Material::new();
        let record = material.directory.path().join("spawn-record");
        let script = format!(
            "#!/bin/sh\nprintf '%s\\n' \"$@\" > '{}'\nprintf 'terminal-marker\\n'\nprintf 'Authenticated to synthetic.example using \"publickey\".\\n' >&2\n",
            record.display()
        );
        write(&material.executable, script.as_bytes(), 0o700);
        let (_target, prepared) = prepared_runtime_fixture(&material).await;
        let spec = super::SshSpawnSpec::build(&prepared, "ignored").unwrap();
        assert_eq!(spec.executable(), material.executable);
        assert_eq!(
            spec.executable().file_name().unwrap(),
            std::ffi::OsStr::new("ssh")
        );
        assert!(!spec.argv().iter().any(|value| value == "-c"));

        let expected_record = spec
            .argv()
            .iter()
            .flat_map(|argument| {
                let mut bytes =
                    std::os::unix::ffi::OsStrExt::as_bytes(argument.as_os_str()).to_vec();
                bytes.push(b'\n');
                bytes
            })
            .collect::<Vec<_>>();
        let running = super::spawn(spec, crate::protocol::Resize::new(80, 24).unwrap())
            .expect("spawn literal SSH executable");
        let (mut terminal, _writer, mut child, mut diagnostics, _client_log) = running.into_parts();
        let mut terminal_bytes = Vec::new();
        let mut diagnostic_bytes = Vec::new();
        tokio::io::AsyncReadExt::read_to_end(&mut terminal, &mut terminal_bytes)
            .await
            .unwrap();
        tokio::io::AsyncReadExt::read_to_end(&mut diagnostics, &mut diagnostic_bytes)
            .await
            .unwrap();
        assert!(child.wait().await.unwrap().success());
        assert!(
            terminal_bytes
                .windows(15)
                .any(|value| value == b"terminal-marker")
        );
        assert!(
            !terminal_bytes
                .windows(13)
                .any(|value| value == b"Authenticated")
        );
        assert!(
            diagnostic_bytes
                .windows(13)
                .any(|value| value == b"Authenticated")
        );
        assert_eq!(fs::read(record).unwrap(), expected_record);
    }

    #[tokio::test]
    async fn ssh_spawn_rechecks_material_after_argv_construction() {
        let material = Material::new();
        let (_target, prepared) = prepared_runtime_fixture(&material).await;
        let spec = super::SshSpawnSpec::build(&prepared, "ignored").unwrap();
        let replacement = material.directory.path().join("known-hosts-replacement");
        write(&replacement, KNOWN_HOST, 0o644);
        fs::rename(replacement, &material.known_hosts).unwrap();

        assert_eq!(
            super::spawn(spec, crate::protocol::Resize::new(80, 24).unwrap()).unwrap_err(),
            super::SshSpawnError::MaterialChanged
        );
    }

    #[tokio::test]
    async fn ssh_argv_loads_no_ambient_configuration() {
        let material = Material::new();
        let (_target, prepared) = prepared_runtime_fixture(&material).await;
        let spec = super::SshSpawnSpec::build(&prepared, "ignored").unwrap();
        let argv = spec.argv();
        assert_eq!(
            argv.windows(2)
                .filter(|pair| pair[0] == "-F" && pair[1] == "/dev/null")
                .count(),
            1
        );
        assert_eq!(
            runtime_options(argv)
                .iter()
                .filter(|option| **option == "CanonicalizeHostname=no")
                .count(),
            1
        );
    }

    #[tokio::test]
    async fn ssh_argv_disables_password_keyboard_interactive_agent_x11_forwarding_proxy_and_local_commands()
     {
        let material = Material::new();
        let (_target, prepared) = prepared_runtime_fixture(&material).await;
        let spec = super::SshSpawnSpec::build(&prepared, "ignored").unwrap();
        let options = runtime_options(spec.argv());
        for required in [
            "PasswordAuthentication=no",
            "KbdInteractiveAuthentication=no",
            "ChallengeResponseAuthentication=no",
            "ForwardAgent=no",
            "ForwardX11=no",
            "ForwardX11Trusted=no",
            "ProxyCommand=none",
            "ProxyJump=none",
            "PermitLocalCommand=no",
        ] {
            assert!(options.contains(&required), "missing {required}");
        }
    }

    #[tokio::test]
    async fn ssh_argv_authority_comes_only_from_typed_target_and_resolved_policy() {
        let material = Material::new();
        let (mut target, _prepared) = prepared_runtime_fixture(&material).await;
        target.port = 22022;
        target.user_policy = SshUserPolicy::Mapping(std::collections::BTreeMap::from([(
            "browser-user".into(),
            "remote-user".into(),
        )]));
        let prepared = prepare_target_with_probe(&target, accept_probe)
            .await
            .unwrap();
        let spec = super::SshSpawnSpec::build(&prepared, "browser-user").unwrap();
        let argv = spec.argv();
        assert_eq!(
            &argv[argv.len() - 6..],
            ["-p", "22022", "-l", "remote-user", "--", "host.example"].map(OsString::from)
        );
        assert!(!argv.iter().any(|value| value == "browser-user"));
        assert_eq!(
            runtime_options(argv)
                .iter()
                .find(|value| value.starts_with("UserKnownHostsFile="))
                .unwrap(),
            &format!("UserKnownHostsFile={}", material.known_hosts.display())
        );
        assert_eq!(
            runtime_options(argv)
                .iter()
                .find(|value| value.starts_with("IdentityFile="))
                .unwrap(),
            &format!("IdentityFile={}", material.identity.display())
        );
    }

    #[tokio::test]
    async fn hostile_browser_and_identity_values_cannot_alter_ssh_argv_structure() {
        let material = Material::new();
        let (mut target, _prepared) = prepared_runtime_fixture(&material).await;
        target.user_policy = SshUserPolicy::SameAsAuthenticatedUser;
        let prepared = prepare_target_with_probe(&target, accept_probe)
            .await
            .unwrap();
        for hostile in [
            "-oProxyCommand=touch /tmp/nope",
            "operator\nProxyCommand=unsafe",
            "operаtor",
        ] {
            assert!(super::SshSpawnSpec::build(&prepared, hostile).is_err());
        }
    }

    #[tokio::test]
    async fn ssh_environment_is_cleared_and_contains_only_fixed_locale_and_term() {
        let material = Material::new();
        let record = material.directory.path().join("environment-record");
        let source = material.directory.path().join("environment-recorder.c");
        let program = format!(
            "#include <stdio.h>\n#include <stdlib.h>\n#include <string.h>\nextern char **environ;\nstatic int compare(const void *left, const void *right) {{ return strcmp(*(const char *const *)left, *(const char *const *)right); }}\nint main(void) {{ size_t count = 0; while (environ[count] != NULL) count++; qsort(environ, count, sizeof(char *), compare); FILE *record = fopen(\"{}\", \"w\"); if (record == NULL) return 2; for (size_t index = 0; index < count; index++) fprintf(record, \"%s\\n\", environ[index]); return fclose(record) == 0 ? 0 : 3; }}\n",
            record.display()
        );
        write(&source, program.as_bytes(), 0o600);
        assert!(
            std::process::Command::new("cc")
                .args(["-Wall", "-Wextra", "-Werror"])
                .arg(&source)
                .arg("-o")
                .arg(&material.executable)
                .status()
                .unwrap()
                .success()
        );
        let (_target, prepared) = prepared_runtime_fixture(&material).await;
        let spec = super::SshSpawnSpec::build(&prepared, "ignored").unwrap();
        assert_eq!(
            spec.environment(),
            [("LANG", "C"), ("LC_ALL", "C"), ("TERM", "xterm-256color")]
        );
        for forbidden in ["PATH", "HOME", "USER", "SSH_AUTH_SOCK"] {
            assert!(
                !spec
                    .environment()
                    .iter()
                    .any(|(name, _)| *name == forbidden)
            );
        }
        let running = super::spawn(spec, crate::protocol::Resize::new(80, 24).unwrap())
            .expect("spawn environment recorder");
        let (_reader, _writer, mut child, _diagnostics, _client_log) = running.into_parts();
        assert!(child.wait().await.unwrap().success());
        assert_eq!(
            fs::read_to_string(record).unwrap(),
            "LANG=C\nLC_ALL=C\nTERM=xterm-256color\n"
        );
    }

    #[test]
    fn ssh_classifier_distinguishes_unknown_mismatch_transport_authentication_and_generic_failure()
    {
        use super::SshDiagnosticClass::{
            Authenticated, AuthenticationFailed, ConnectionFailed, GenericFailure, HostKeyMismatch,
            UnknownHostKey,
        };

        for (diagnostic, expected) in [
            (
                b"No ED25519 host key is known for host.example and you have requested strict checking.\r\n"
                    .as_slice(),
                UnknownHostKey,
            ),
            (
                b"WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!\n".as_slice(),
                HostKeyMismatch,
            ),
            (
                b"ssh: connect to host host.example port 22: Connection refused\n".as_slice(),
                ConnectionFailed,
            ),
            (
                b"operator@host.example: Permission denied (publickey).\n".as_slice(),
                AuthenticationFailed,
            ),
            (
                b"Authenticated to host.example ([192.0.2.1]:22) using \"publickey\".\n".as_slice(),
                Authenticated,
            ),
            (b"ssh: unexplained failure\n".as_slice(), GenericFailure),
        ] {
            let mut classifier = super::SshDiagnosticClassifier::new("host.example");
            classifier.push(diagnostic);
            assert_eq!(classifier.finish(), expected);
        }
    }

    #[test]
    fn ssh_classifier_exposes_live_setup_classification_before_eof() {
        use super::SshDiagnosticClass::{
            Authenticated, AuthenticationFailed, ConnectionFailed, GenericFailure, HostKeyMismatch,
            UnknownHostKey,
        };

        for (diagnostic, expected) in [
            (
                b"Authenticated to host.example ([192.0.2.1]:22) using \"publickey\".\n".as_slice(),
                Authenticated,
            ),
            (
                b"WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!\n".as_slice(),
                HostKeyMismatch,
            ),
            (
                b"No ED25519 host key is known for host.example and you have requested strict checking.\n"
                    .as_slice(),
                UnknownHostKey,
            ),
            (
                b"ssh: connect to host host.example port 22: Connection refused\n".as_slice(),
                ConnectionFailed,
            ),
            (
                b"operator@host.example: Permission denied (publickey).\n".as_slice(),
                AuthenticationFailed,
            ),
        ] {
            let mut classifier = super::SshDiagnosticClassifier::new("host.example");
            classifier.push(diagnostic);
            assert_eq!(classifier.classification(), Some(expected));
            assert_eq!(classifier.classification(), Some(expected));
        }

        let mut precedence = super::SshDiagnosticClassifier::new("host.example");
        precedence.push(b"Authenticated to host.example using \"publickey\".\n");
        assert_eq!(precedence.classification(), Some(Authenticated));
        precedence.push(b"WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!\n");
        assert_eq!(precedence.classification(), Some(HostKeyMismatch));

        let mut partial = super::SshDiagnosticClassifier::new("host.example");
        partial.push(b"Authenticated to host.example using \"public");
        assert_eq!(partial.classification(), None);

        let mut split_utf8 = super::SshDiagnosticClassifier::new("host.example");
        split_utf8.push(b"setup caf\xc3");
        assert_eq!(split_utf8.classification(), None);
        split_utf8.push(b"\xa9\n");
        assert_eq!(split_utf8.classification(), None);

        let mut invalid_utf8 = super::SshDiagnosticClassifier::new("host.example");
        invalid_utf8.push(&[0xff]);
        assert_eq!(invalid_utf8.classification(), Some(GenericFailure));

        let mut unrecognized = super::SshDiagnosticClassifier::new("host.example");
        unrecognized.push(b"debug1: setup continues\n");
        assert_eq!(unrecognized.classification(), None);
        assert_eq!(unrecognized.finish(), GenericFailure);

        let mut bounded = super::SshDiagnosticClassifier::new("host.example");
        bounded.push(&[b'x'; super::MAX_SSH_DIAGNOSTIC_BYTES + 1]);
        assert_eq!(bounded.classification(), Some(GenericFailure));
    }

    #[test]
    fn ssh_classifier_is_bounded_locale_pinned_and_never_returns_diagnostics() {
        use super::{SshDiagnosticClass, SshDiagnosticClassifier};

        let mut oversized = SshDiagnosticClassifier::new("host.example");
        oversized.push(&[b'x'; super::MAX_SSH_DIAGNOSTIC_BYTES + 1]);
        assert_eq!(oversized.finish(), SshDiagnosticClass::GenericFailure);

        let mut too_many_lines = SshDiagnosticClassifier::new("host.example");
        too_many_lines.push(&[b'\n'; super::MAX_SSH_DIAGNOSTIC_LINES + 1]);
        assert_eq!(too_many_lines.finish(), SshDiagnosticClass::GenericFailure);
        let mut trailing_extra_line = SshDiagnosticClassifier::new("host.example");
        trailing_extra_line.push(&[b'\n'; super::MAX_SSH_DIAGNOSTIC_LINES]);
        trailing_extra_line.push(b"Authenticated to synthetic using \"publickey\".");
        assert_eq!(
            trailing_extra_line.finish(),
            SshDiagnosticClass::GenericFailure
        );

        let mut long_line = SshDiagnosticClassifier::new("host.example");
        long_line.push(&[b'x'; super::MAX_SSH_DIAGNOSTIC_LINE_BYTES + 1]);
        assert_eq!(long_line.finish(), SshDiagnosticClass::GenericFailure);

        let mut invalid_utf8 = SshDiagnosticClassifier::new("host.example");
        invalid_utf8.push(&[0xff]);
        assert_eq!(invalid_utf8.finish(), SshDiagnosticClass::GenericFailure);

        let debug = format!("{:?}", {
            let mut classifier = SshDiagnosticClassifier::new("host.example");
            classifier.push(b"secret-host secret-user /secret/path");
            classifier
        });
        assert!(!debug.contains("secret"));
    }

    #[tokio::test]
    async fn prepared_ssh_authority_is_complete_redacted_and_policy_denial_is_exact() {
        let material = Material::new();
        let (target, prepared) = prepared_runtime_fixture(&material).await;
        let mutations: [fn(&mut SshTarget); 5] = [
            |target: &mut SshTarget| target.host = "other.example".into(),
            |target: &mut SshTarget| target.port = 22022,
            |target: &mut SshTarget| {
                target.user_policy = SshUserPolicy::Fixed("other-user".into());
            },
            |target: &mut SshTarget| target.read_only = true,
            |target: &mut SshTarget| target.identity_file = "/different/identity".into(),
        ];
        for mutate in mutations {
            let mut changed = target.clone();
            mutate(&mut changed);
            assert!(!prepared.matches_target(&changed));
        }

        let denied_target = SshTarget {
            user_policy: SshUserPolicy::Mapping(std::collections::BTreeMap::new()),
            ..target
        };
        let denied = prepare_target_with_probe(&denied_target, accept_probe)
            .await
            .unwrap();
        assert_eq!(
            super::SshSpawnSpec::build(&denied, "missing-user").unwrap_err(),
            super::SshSpawnError::PolicyDenied
        );

        let debug = format!("{prepared:?}");
        for secret in [
            material.executable.to_str().unwrap(),
            material.known_hosts.to_str().unwrap(),
            material.identity.to_str().unwrap(),
            "host.example",
            "operator",
        ] {
            assert!(!debug.contains(secret));
        }
    }

    #[test]
    fn ssh_authenticated_classifier_requires_exact_complete_expected_host_line() {
        use super::SshDiagnosticClass::Authenticated;

        let mut classifier = super::SshDiagnosticClassifier::new("host.example");
        classifier.push(b"Authenticated to host.example using \"publickey\".");
        assert_eq!(classifier.classification(), None);
        classifier.push(b"\n");
        assert_eq!(classifier.classification(), Some(Authenticated));

        for rejected in [
            b"prefix Authenticated to host.example using \"publickey\".\n".as_slice(),
            b"Authenticated to host.example using \"publickey\". suffix\n".as_slice(),
            b"Authenticated to other.example using \"publickey\".\n".as_slice(),
            b"Authenticated to host.example\nusing \"publickey\".\n".as_slice(),
            b"remote banner: Authenticated to host.example using \"publickey\".\n".as_slice(),
        ] {
            let mut classifier = super::SshDiagnosticClassifier::new("host.example");
            classifier.push(rejected);
            assert_eq!(classifier.classification(), None);
        }
    }

    #[tokio::test]
    async fn ssh_admission_uses_private_fifo_and_never_raw_stderr() {
        let material = Material::new();
        let script = b"#!/bin/sh\nwhile [ \"$1\" != \"-E\" ]; do shift; done\nlog=$2\nsleep 1\nprintf 'debug1: setup continues\\n' > \"$log\"\nprintf 'Authenticated to host.example using \"publickey\".\\n' >&2\nsleep 1\nprintf 'Authenticated to host.example using \"publickey\".\\n' > \"$log\"\n";
        write(&material.executable, script, 0o700);
        let (_target, prepared) = prepared_runtime_fixture(&material).await;
        let spec = super::SshSpawnSpec::build(&prepared, "ignored").unwrap();
        let fifo_path = spec.client_log_path_for_test().to_owned();
        let metadata = fs::metadata(&fifo_path).unwrap();
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
        assert_eq!(
            fs::metadata(fifo_path.parent().unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );

        let running = super::spawn(spec, crate::protocol::Resize::new(80, 24).unwrap()).unwrap();
        let (_terminal, _writer, mut child, mut raw_stderr, client_log) = running.into_parts();
        let mut trusted = vec![0; 256];
        let setup_count = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            client_log.read(&mut trusted),
        )
        .await
        .unwrap()
        .unwrap();
        let mut classifier = super::SshDiagnosticClassifier::new("host.example");
        classifier.push(&trusted[..setup_count]);
        assert_eq!(classifier.classification(), None);
        let mut raw = Vec::new();
        tokio::io::AsyncReadExt::read_to_end(&mut raw_stderr, &mut raw)
            .await
            .unwrap();
        assert!(raw.windows(17).any(|window| window == b"Authenticated to "));
        assert!(child.wait().await.unwrap().success());
        let count = client_log.read(&mut trusted).await.unwrap();
        classifier.push(&trusted[..count]);
        assert_eq!(
            classifier.classification(),
            Some(super::SshDiagnosticClass::Authenticated)
        );
        drop(client_log);
        assert!(!fifo_path.exists());
    }

    #[tokio::test]
    async fn ssh_client_log_fifo_flood_is_incrementally_drained_and_bounded() {
        let material = Material::new();
        let script = b"#!/bin/sh\nwhile [ \"$1\" != \"-E\" ]; do shift; done\nlog=$2\nwhile :; do printf 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'; done > \"$log\"\n";
        write(&material.executable, script, 0o700);
        let (_target, prepared) = prepared_runtime_fixture(&material).await;
        let spec = super::SshSpawnSpec::build(&prepared, "ignored").unwrap();
        let running = super::spawn(spec, crate::protocol::Resize::new(80, 24).unwrap()).unwrap();
        let (_terminal, _writer, mut child, _raw_stderr, client_log) = running.into_parts();
        let mut classifier = super::SshDiagnosticClassifier::new("host.example");
        let mut total = 0;
        let mut buffer = [0_u8; 1024];
        while classifier.classification() != Some(super::SshDiagnosticClass::GenericFailure) {
            let count = tokio::time::timeout(
                std::time::Duration::from_secs(2),
                client_log.read(&mut buffer),
            )
            .await
            .expect("FIFO flood drain stalled")
            .unwrap();
            assert_ne!(count, 0, "RDWR FIFO must not report premature EOF");
            assert!(count <= buffer.len());
            total += count;
            classifier.push(&buffer[..count]);
        }
        assert!(total <= super::MAX_SSH_DIAGNOSTIC_BYTES + buffer.len());
        child
            .terminate(std::time::Duration::from_millis(100))
            .await
            .unwrap();
        assert_eq!(
            classifier.classification(),
            Some(super::SshDiagnosticClass::GenericFailure)
        );
    }
}
