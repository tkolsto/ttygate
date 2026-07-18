use std::{
    fmt, fs,
    io::{Read, Seek, SeekFrom, Write},
    net::SocketAddr,
    path::{Component, Path, PathBuf},
    sync::{Arc, Mutex, MutexGuard},
    time::SystemTime,
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::Serialize;
use thiserror::Error;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use crate::{
    config::{TargetAllowlist, UnknownTarget},
    ticket::Identity,
};

pub const AUDIT_SCHEMA_VERSION: u8 = 1;
const OPAQUE_ID_BYTES: usize = 16;
const MAX_AUDIT_RECORD_BYTES: usize = 4096;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct AuditTimestamp(String);

impl AuditTimestamp {
    pub fn now() -> Result<Self, AuditValueError> {
        Self::from_system_time(SystemTime::now())
    }

    pub fn from_system_time(value: SystemTime) -> Result<Self, AuditValueError> {
        OffsetDateTime::from(value)
            .format(&Rfc3339)
            .map(Self)
            .map_err(|_| AuditValueError)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

macro_rules! opaque_id {
    ($name:ident) => {
        #[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn generate() -> Result<Self, AuditValueError> {
                let mut bytes = [0_u8; OPAQUE_ID_BYTES];
                getrandom::fill(&mut bytes).map_err(|_| AuditValueError)?;
                Ok(Self::from_bytes(bytes))
            }

            pub fn from_bytes(bytes: [u8; OPAQUE_ID_BYTES]) -> Self {
                Self(URL_SAFE_NO_PAD.encode(bytes))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }
    };
}

opaque_id!(SessionId);
opaque_id!(CorrelationId);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedAuditTarget(String);

impl ResolvedAuditTarget {
    pub fn resolve(targets: &TargetAllowlist, name: &str) -> Result<Self, UnknownTarget> {
        targets
            .resolve(name)
            .map(|target| Self(target.name().to_owned()))
    }

    pub(crate) fn from_resolved_name(name: &str) -> Self {
        Self(name.to_owned())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum DenialCategory {
    Authentication,
    RateLimit,
    Capacity,
    Target,
    Ticket,
    Origin,
    HostKey,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum DenialReason {
    IdentityRequired,
    IdentityUnavailable,
    AuthenticationRateLimited,
    SessionRateLimited,
    GlobalSessionLimit,
    IdentitySessionLimit,
    TargetNotFound,
    TargetUnavailable,
    TicketMalformed,
    TicketUnknown,
    TicketExpired,
    TicketWrongIdentity,
    TicketCapacity,
    TicketGeneration,
    OriginDenied,
    HostKeyVerificationFailed,
    UnknownHostKey,
    HostKeyMismatch,
    SshConnectionFailed,
    SshAuthenticationFailed,
    SshUserPolicyDenied,
    SshFailed,
    SessionUnavailable,
    AuditUnavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AuditCloseReason {
    ChildExited,
    Explicit,
    WebsocketDisconnect,
    ProtocolViolation,
    PolicyViolation,
    InternalFailure,
    ManagerShutdown,
    IdleTimeout,
    AbsoluteTimeout,
    SpawnFailure,
    Cancellation,
    SupervisorUnwind,
    BackendFailure,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", content = "value", rename_all = "kebab-case")]
pub enum AuditOutcome {
    Code(u8),
    Signal(u8),
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AuditEvent {
    schema_version: u8,
    #[serde(flatten)]
    event: AuditEventKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "event_type", rename_all = "kebab-case")]
enum AuditEventKind {
    AuthenticationSucceeded {
        identity: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        remote_address: Option<String>,
        occurred_at: AuditTimestamp,
    },
    SessionStarted {
        session_id: SessionId,
        identity: String,
        target: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        remote_address: Option<String>,
        started_at: AuditTimestamp,
    },
    SessionEnded {
        session_id: SessionId,
        identity: String,
        target: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        remote_address: Option<String>,
        started_at: AuditTimestamp,
        ended_at: AuditTimestamp,
        close_reason: AuditCloseReason,
        #[serde(skip_serializing_if = "Option::is_none")]
        outcome: Option<AuditOutcome>,
    },
    AccessDenied {
        correlation_id: CorrelationId,
        category: DenialCategory,
        reason: DenialReason,
        #[serde(skip_serializing_if = "Option::is_none")]
        identity: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        target: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        remote_address: Option<String>,
        occurred_at: AuditTimestamp,
    },
}

impl AuditEvent {
    pub fn authentication_succeeded(
        identity: &Identity,
        remote_address: Option<SocketAddr>,
        occurred_at: AuditTimestamp,
    ) -> Self {
        Self::new(AuditEventKind::AuthenticationSucceeded {
            identity: identity.as_str().to_owned(),
            remote_address: format_address(remote_address),
            occurred_at,
        })
    }

    pub fn session_started(
        session_id: SessionId,
        identity: &Identity,
        target: &ResolvedAuditTarget,
        remote_address: Option<SocketAddr>,
        started_at: AuditTimestamp,
    ) -> Self {
        Self::new(AuditEventKind::SessionStarted {
            session_id,
            identity: identity.as_str().to_owned(),
            target: target.as_str().to_owned(),
            remote_address: format_address(remote_address),
            started_at,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn session_ended(
        session_id: SessionId,
        identity: &Identity,
        target: &ResolvedAuditTarget,
        remote_address: Option<SocketAddr>,
        started_at: AuditTimestamp,
        ended_at: AuditTimestamp,
        close_reason: AuditCloseReason,
        outcome: Option<AuditOutcome>,
    ) -> Self {
        Self::new(AuditEventKind::SessionEnded {
            session_id,
            identity: identity.as_str().to_owned(),
            target: target.as_str().to_owned(),
            remote_address: format_address(remote_address),
            started_at,
            ended_at,
            close_reason,
            outcome,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn access_denied(
        correlation_id: CorrelationId,
        category: DenialCategory,
        reason: DenialReason,
        identity: Option<&Identity>,
        target: Option<&ResolvedAuditTarget>,
        remote_address: Option<SocketAddr>,
        occurred_at: AuditTimestamp,
    ) -> Self {
        Self::new(AuditEventKind::AccessDenied {
            correlation_id,
            category,
            reason,
            identity: identity.map(|identity| identity.as_str().to_owned()),
            target: target.map(|target| target.as_str().to_owned()),
            remote_address: format_address(remote_address),
            occurred_at,
        })
    }

    fn new(event: AuditEventKind) -> Self {
        Self {
            schema_version: AUDIT_SCHEMA_VERSION,
            event,
        }
    }
}

fn format_address(address: Option<SocketAddr>) -> Option<String> {
    address.map(|address| address.to_string())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("audit value could not be constructed")]
pub struct AuditValueError;

impl fmt::Display for SessionId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl fmt::Display for CorrelationId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Clone)]
pub struct AuditLog {
    inner: Arc<Mutex<AuditWriterState>>,
}

struct AuditWriterState {
    writer: Box<dyn Write + Send>,
    failed: bool,
}

pub struct AuditAuthorityGuard<'a> {
    _state: MutexGuard<'a, AuditWriterState>,
}

impl fmt::Debug for AuditLog {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("AuditLog").finish_non_exhaustive()
    }
}

impl AuditLog {
    pub fn open(path: &Path) -> Result<Self, AuditError> {
        Self::open_with_owner_and_hook(path, nix::unistd::geteuid().as_raw(), || {})
    }

    #[cfg(test)]
    fn open_with_parent_hook(
        path: &Path,
        parent_opened: impl FnOnce(),
    ) -> Result<Self, AuditError> {
        Self::open_with_owner_and_hook(path, nix::unistd::geteuid().as_raw(), parent_opened)
    }

    #[cfg(test)]
    fn open_with_expected_owner(path: &Path, expected_owner: u32) -> Result<Self, AuditError> {
        Self::open_with_owner_and_hook(path, expected_owner, || {})
    }

    fn open_with_owner_and_hook(
        path: &Path,
        expected_owner: u32,
        parent_opened: impl FnOnce(),
    ) -> Result<Self, AuditError> {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        validate_audit_path(path)?;
        let mut file = open_anchored_audit_file(path, parent_opened)?;
        let metadata = file
            .metadata()
            .map_err(|_| AuditError::DestinationUnavailable)?;
        if !metadata.file_type().is_file()
            || metadata.permissions().mode() & 0o077 != 0
            || metadata.uid() != expected_owner
        {
            return Err(AuditError::UnsafeDestination);
        }
        validate_complete_tail(&mut file, metadata.len())?;
        Ok(Self::from_writer(file))
    }

    pub fn record(&self, event: &AuditEvent) -> Result<(), AuditError> {
        let mut record =
            serde_json::to_vec(event).map_err(|_| AuditError::SerializationUnavailable)?;
        record.push(b'\n');
        if record.len() > MAX_AUDIT_RECORD_BYTES {
            return Err(AuditError::RecordTooLarge);
        }

        let mut state = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if state.failed {
            return Err(AuditError::Unavailable);
        }
        let result = state
            .writer
            .write(&record)
            .and_then(|count| {
                if count == record.len() {
                    Ok(())
                } else {
                    Err(std::io::Error::new(
                        std::io::ErrorKind::WriteZero,
                        "incomplete audit append",
                    ))
                }
            })
            .and_then(|()| state.writer.flush());
        if result.is_err() {
            state.failed = true;
            return Err(AuditError::Unavailable);
        }
        Ok(())
    }

    pub fn is_available(&self) -> bool {
        !self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .failed
    }

    pub fn authority_guard(&self) -> Result<AuditAuthorityGuard<'_>, AuditError> {
        let state = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if state.failed {
            return Err(AuditError::Unavailable);
        }
        Ok(AuditAuthorityGuard { _state: state })
    }

    #[cfg(test)]
    pub(crate) fn fail_for_test(&self) {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .failed = true;
    }

    fn from_writer(writer: impl Write + Send + 'static) -> Self {
        Self {
            inner: Arc::new(Mutex::new(AuditWriterState {
                writer: Box::new(writer),
                failed: false,
            })),
        }
    }
}

fn open_anchored_audit_file(
    path: &Path,
    parent_opened: impl FnOnce(),
) -> Result<fs::File, AuditError> {
    use rustix::fs::{Mode, OFlags, open, openat};

    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let mut directory = open(
        if parent.is_absolute() { "/" } else { "." },
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| AuditError::DestinationUnavailable)?;
    for component in parent.components() {
        let name = match component {
            Component::RootDir | Component::CurDir => continue,
            Component::ParentDir => std::ffi::OsStr::new(".."),
            Component::Normal(name) => name,
            Component::Prefix(_) => return Err(AuditError::UnsafeDestination),
        };
        directory = openat(
            &directory,
            name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| AuditError::UnsafeDestination)?;
    }
    parent_opened();
    let file_name = path.file_name().ok_or(AuditError::UnsafeDestination)?;
    let file = openat(
        &directory,
        file_name,
        OFlags::RDWR
            | OFlags::APPEND
            | OFlags::CREATE
            | OFlags::NOFOLLOW
            | OFlags::NONBLOCK
            | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    )
    .map_err(|_| AuditError::DestinationUnavailable)?;
    Ok(fs::File::from(file))
}

fn validate_audit_path(path: &Path) -> Result<(), AuditError> {
    if path.as_os_str().is_empty() || path.file_name().is_none() {
        return Err(AuditError::UnsafeDestination);
    }
    validate_parent_components(path.parent().unwrap_or_else(|| Path::new(".")))?;
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.file_type().is_file() => {
            Err(AuditError::UnsafeDestination)
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(AuditError::DestinationUnavailable),
    }
}

fn validate_parent_components(parent: &Path) -> Result<(), AuditError> {
    let mut current = if parent.is_absolute() {
        PathBuf::from("/")
    } else {
        PathBuf::from(".")
    };
    for component in parent.components() {
        match component {
            Component::Prefix(_) => return Err(AuditError::UnsafeDestination),
            Component::RootDir => continue,
            Component::CurDir => {}
            Component::ParentDir => current.push(".."),
            Component::Normal(component) => current.push(component),
        }
        let metadata =
            fs::symlink_metadata(&current).map_err(|_| AuditError::DestinationUnavailable)?;
        if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
            return Err(AuditError::UnsafeDestination);
        }
    }
    Ok(())
}

fn validate_complete_tail(file: &mut fs::File, length: u64) -> Result<(), AuditError> {
    if length == 0 {
        return Ok(());
    }
    file.seek(SeekFrom::End(-1))
        .map_err(|_| AuditError::DestinationUnavailable)?;
    let mut final_byte = [0_u8; 1];
    file.read_exact(&mut final_byte)
        .map_err(|_| AuditError::DestinationUnavailable)?;
    if final_byte[0] != b'\n' {
        return Err(AuditError::IncompleteExistingLog);
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum AuditError {
    #[error("audit destination is unsafe")]
    UnsafeDestination,
    #[error("audit destination is unavailable")]
    DestinationUnavailable,
    #[error("audit log ends with an incomplete record")]
    IncompleteExistingLog,
    #[error("audit record is too large")]
    RecordTooLarge,
    #[error("audit serialization is unavailable")]
    SerializationUnavailable,
    #[error("audit writer is unavailable")]
    Unavailable,
}

#[cfg(test)]
mod sink_failure_tests {
    use std::{
        fs,
        io::{self, Write},
        sync::{Arc, Condvar, Mutex},
        thread,
    };

    use super::{
        AuditError, AuditEvent, AuditLog, AuditTimestamp, CorrelationId, DenialCategory,
        DenialReason,
    };

    struct FailAfterOneWrite {
        bytes: Arc<Mutex<Vec<u8>>>,
        writes: usize,
    }

    struct BlockingFailure {
        state: Arc<(Mutex<(bool, bool)>, Condvar)>,
    }

    impl Write for BlockingFailure {
        fn write(&mut self, _bytes: &[u8]) -> io::Result<usize> {
            let (lock, changed) = &*self.state;
            let mut state = lock.lock().unwrap();
            state.0 = true;
            changed.notify_all();
            while !state.1 {
                state = changed.wait(state).unwrap();
            }
            Err(io::Error::other("simulated concurrent disk failure"))
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl Write for FailAfterOneWrite {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if self.writes > 0 {
                return Err(io::Error::other("simulated disk failure"));
            }
            self.writes += 1;
            self.bytes.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn event(sequence: u8) -> AuditEvent {
        AuditEvent::access_denied(
            CorrelationId::from_bytes([sequence; 16]),
            DenialCategory::Authentication,
            DenialReason::IdentityRequired,
            None,
            None,
            None,
            AuditTimestamp::from_system_time(std::time::SystemTime::UNIX_EPOCH).unwrap(),
        )
    }

    #[test]
    fn runtime_write_failure_permanently_poisoned_sink_without_corrupting_complete_records() {
        let bytes = Arc::new(Mutex::new(Vec::new()));
        let log = AuditLog::from_writer(FailAfterOneWrite {
            bytes: Arc::clone(&bytes),
            writes: 0,
        });

        log.record(&event(1)).unwrap();
        assert_eq!(log.record(&event(2)), Err(AuditError::Unavailable));
        assert_eq!(log.record(&event(3)), Err(AuditError::Unavailable));

        let contents = String::from_utf8(bytes.lock().unwrap().clone()).unwrap();
        assert_eq!(contents.lines().count(), 1);
        assert!(contents.ends_with('\n'));
        assert!(serde_json::from_str::<serde_json::Value>(contents.trim_end()).is_ok());
    }

    #[test]
    fn audit_authority_guard_linearizes_with_runtime_failure() {
        let state = Arc::new((Mutex::new((false, false)), Condvar::new()));
        let log = Arc::new(AuditLog::from_writer(BlockingFailure {
            state: Arc::clone(&state),
        }));
        let writer = {
            let log = Arc::clone(&log);
            thread::spawn(move || assert_eq!(log.record(&event(1)), Err(AuditError::Unavailable)))
        };
        {
            let (lock, changed) = &*state;
            let mut state = lock.lock().unwrap();
            while !state.0 {
                state = changed.wait(state).unwrap();
            }
        }
        let authority = {
            let log = Arc::clone(&log);
            thread::spawn(move || log.authority_guard().map(drop))
        };
        {
            let (lock, changed) = &*state;
            let mut state = lock.lock().unwrap();
            state.1 = true;
            changed.notify_all();
        }
        writer.join().unwrap();
        assert_eq!(authority.join().unwrap(), Err(AuditError::Unavailable));
    }

    #[test]
    fn parent_rename_race_cannot_redirect_audit_destination() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
        let parent = directory.path().join("parent");
        let moved = directory.path().join("moved");
        let alternate = directory.path().join("alternate");
        fs::create_dir(&parent).unwrap();
        fs::create_dir(&alternate).unwrap();
        let path = parent.join("audit.jsonl");
        let log = AuditLog::open_with_parent_hook(&path, || {
            fs::rename(&parent, &moved).unwrap();
            symlink(&alternate, &parent).unwrap();
        })
        .unwrap();
        log.record(&event(1)).unwrap();

        assert!(moved.join("audit.jsonl").is_file());
        assert!(!alternate.join("audit.jsonl").exists());
    }

    #[test]
    fn audit_open_race_with_fifo_never_blocks_or_accepts_special_file() {
        let directory = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
        let path = directory.path().join("audit.jsonl");
        let result = AuditLog::open_with_parent_hook(&path, || {
            nix::unistd::mkfifo(
                &path,
                nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
            )
            .unwrap();
        });

        assert_eq!(result.unwrap_err(), AuditError::UnsafeDestination);
    }

    #[test]
    fn audit_open_rejects_existing_file_not_owned_by_daemon() {
        let directory = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
        let path = directory.path().join("audit.jsonl");
        fs::write(&path, b"").unwrap();
        let wrong_owner = nix::unistd::geteuid().as_raw().wrapping_add(1);

        assert_eq!(
            AuditLog::open_with_expected_owner(&path, wrong_owner).unwrap_err(),
            AuditError::UnsafeDestination
        );
    }
}
