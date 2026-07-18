use std::{
    collections::BTreeMap,
    fs::{self, File},
    future::Future,
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};

use base64::{Engine, engine::general_purpose::STANDARD};
use thiserror::Error;
use tokio::{io::AsyncReadExt, process::Command, time::timeout};

use crate::config::{SshTarget, Target};

pub const MAX_SSH_EXECUTABLE_BYTES: u64 = 16 * 1024 * 1024;
pub const MAX_KNOWN_HOSTS_BYTES: u64 = 4 * 1024 * 1024;
pub const MAX_IDENTITY_BYTES: u64 = 1024 * 1024;
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
    let mut argv = Vec::with_capacity(STRICT_SSH_PROBE_OPTIONS.len() * 2 + 5);
    argv.extend(["-G", "-F", "/dev/null"]);
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

#[derive(Debug, Clone)]
pub struct PreparedSshTarget {
    name: String,
    executable: PathBuf,
    executable_snapshot: FileSnapshot,
    known_hosts: PathBuf,
    known_hosts_snapshot: FileSnapshot,
    identity: PathBuf,
    identity_snapshot: FileSnapshot,
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
}

#[derive(Debug, Clone, Default)]
pub struct PreparedSshTargets {
    targets: BTreeMap<String, PreparedSshTarget>,
}

impl PreparedSshTargets {
    pub fn get(&self, name: &str) -> Option<&PreparedSshTarget> {
        self.targets.get(name)
    }

    pub fn iter(&self) -> impl Iterator<Item = &PreparedSshTarget> {
        self.targets.values()
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
    let stdout = child
        .stdout
        .take()
        .ok_or(SshPreparationError::CapabilityUnsupported)?;
    let stderr = child
        .stderr
        .take()
        .ok_or(SshPreparationError::CapabilityUnsupported)?;
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
    .await
    .map_err(|_| SshPreparationError::CapabilityUnsupported)?;
    let (status, stdout, stderr) = completed;
    let status = status.map_err(|_| SshPreparationError::CapabilityUnsupported)?;
    let stdout = stdout.map_err(|_| SshPreparationError::CapabilityUnsupported)?;
    let stderr = stderr.map_err(|_| SshPreparationError::CapabilityUnsupported)?;
    if !status.success()
        || stdout.len() as u64 > MAX_PROBE_OUTPUT_BYTES
        || stderr.len() as u64 > MAX_PROBE_OUTPUT_BYTES
    {
        return Err(SshPreparationError::CapabilityUnsupported);
    }
    let output =
        std::str::from_utf8(&stdout).map_err(|_| SshPreparationError::CapabilityUnsupported)?;
    let normalized = output.to_ascii_lowercase();
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
    if required_values
        .iter()
        .any(|(key, values)| !has_probe_value(&normalized, key, values))
    {
        return Err(SshPreparationError::CapabilityUnsupported);
    }
    Ok(())
}

fn has_probe_value(output: &str, key: &str, allowed_values: &[&str]) -> bool {
    output.lines().any(|line| {
        line.split_once(char::is_whitespace)
            .is_some_and(|(found_key, value)| {
                found_key == key && allowed_values.contains(&value.trim())
            })
    })
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
    let mut private_block = take_ssh_string(&mut remaining)?;
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
        && bytes.len() <= u8::MAX as usize
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
    let value = remaining
        .get(4..4 + length)
        .ok_or(SshPreparationError::IdentityUnsafe)?;
    *remaining = remaining
        .get(4 + length..)
        .ok_or(SshPreparationError::IdentityUnsafe)?;
    Ok(value)
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

    fn unencrypted_identity() -> Vec<u8> {
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
        private.extend_from_slice(&[1, 2, 3, 4]);
        string(&mut binary, &private);
        pem_identity(&binary)
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
        assert_eq!(&argv[..3], ["-G", "-F", "/dev/null"]);
        assert_eq!(
            &argv[argv.len() - 2..],
            ["--", "ttygate-capability.invalid"]
        );
        let option_argv = &argv[3..argv.len() - 2];
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
}
