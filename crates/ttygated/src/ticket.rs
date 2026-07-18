use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use thiserror::Error;

use crate::{config::Target, session::SessionReservation};

const TOKEN_BYTES: usize = 32;
const TOKEN_LENGTH: usize = 43;

pub trait Clock: Send + Sync {
    fn now(&self) -> Instant;
}
pub trait TicketGenerator: Send + Sync {
    fn generate(&self) -> Result<[u8; TOKEN_BYTES], TicketError>;
}

struct SystemClock;
impl Clock for SystemClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
}

struct OsTicketGenerator;
impl TicketGenerator for OsTicketGenerator {
    fn generate(&self) -> Result<[u8; TOKEN_BYTES], TicketError> {
        let mut bytes = [0_u8; TOKEN_BYTES];
        getrandom::fill(&mut bytes).map_err(|_| TicketError::Generation)?;
        Ok(bytes)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Identity(String);

impl Identity {
    pub fn new(value: impl Into<String>) -> Result<Self, IdentityError> {
        let value = value.into();
        if value.is_empty() || value.len() > 128 || value.chars().any(char::is_control) {
            return Err(IdentityError);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("invalid identity")]
pub struct IdentityError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ticket(String);

impl Ticket {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TicketExpiry(Instant);

impl TicketExpiry {
    pub(crate) fn instant(self) -> Instant {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum TicketError {
    #[error("ticket is malformed")]
    Malformed,
    #[error("ticket is unknown")]
    Unknown,
    #[error("ticket has expired")]
    Expired,
    #[error("ticket belongs to another identity")]
    WrongIdentity,
    #[error("ticket capacity is exhausted")]
    AtCapacity,
    #[error("ticket generation failed")]
    Generation,
}

#[derive(Debug)]
struct Entry {
    identity: Identity,
    target: Target,
    expires_at: Instant,
    reservation: SessionReservation,
}

#[derive(Debug)]
pub struct TicketGrant {
    target: Target,
    reservation: SessionReservation,
}

impl TicketGrant {
    pub fn target(&self) -> &Target {
        &self.target
    }

    pub fn into_parts(self) -> (Target, SessionReservation) {
        (self.target, self.reservation)
    }
}

pub struct TicketStore {
    ttl: Duration,
    capacity: usize,
    entries: Mutex<HashMap<String, Entry>>,
    clock: Arc<dyn Clock>,
    generator: Arc<dyn TicketGenerator>,
}

impl TicketStore {
    pub fn new(ttl: Duration, capacity: usize) -> Self {
        Self::with_sources(
            ttl,
            capacity,
            Arc::new(SystemClock),
            Arc::new(OsTicketGenerator),
        )
    }

    pub fn with_sources(
        ttl: Duration,
        capacity: usize,
        clock: Arc<dyn Clock>,
        generator: Arc<dyn TicketGenerator>,
    ) -> Self {
        Self {
            ttl,
            capacity,
            entries: Mutex::new(HashMap::with_capacity(capacity.min(1024))),
            clock,
            generator,
        }
    }

    pub fn ttl(&self) -> Duration {
        self.ttl
    }

    pub fn issue(
        &self,
        identity: Identity,
        target: Target,
        reservation: SessionReservation,
    ) -> Result<Ticket, TicketError> {
        self.issue_at(identity, target, reservation, self.next_expiry())
    }

    pub(crate) fn next_expiry(&self) -> TicketExpiry {
        TicketExpiry(self.clock.now() + self.ttl)
    }

    pub(crate) fn issue_at(
        &self,
        identity: Identity,
        target: Target,
        reservation: SessionReservation,
        expiry: TicketExpiry,
    ) -> Result<Ticket, TicketError> {
        let now = self.clock.now();
        if expiry.instant() <= now {
            return Err(TicketError::Expired);
        }
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        entries.retain(|_, entry| entry.expires_at > now);
        if entries.len() >= self.capacity {
            return Err(TicketError::AtCapacity);
        }
        for _ in 0..4 {
            let bytes = self.generator.generate()?;
            if expiry.instant() <= self.clock.now() {
                return Err(TicketError::Expired);
            }
            let token = URL_SAFE_NO_PAD.encode(bytes);
            if !entries.contains_key(&token) {
                entries.insert(
                    token.clone(),
                    Entry {
                        identity,
                        target,
                        expires_at: expiry.instant(),
                        reservation,
                    },
                );
                return Ok(Ticket(token));
            }
        }
        Err(TicketError::Generation)
    }

    pub fn redeem(&self, ticket: &str, identity: &Identity) -> Result<TicketGrant, TicketError> {
        if ticket.len() != TOKEN_LENGTH
            || !ticket
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err(TicketError::Malformed);
        }
        let now = self.clock.now();
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let entry = entries.get(ticket).ok_or(TicketError::Unknown)?;
        if entry.expires_at <= now {
            entries.remove(ticket);
            return Err(TicketError::Expired);
        }
        if &entry.identity != identity {
            return Err(TicketError::WrongIdentity);
        }
        let entry = entries.remove(ticket).expect("entry was checked");
        Ok(TicketGrant {
            target: entry.target,
            reservation: entry.reservation,
        })
    }

    pub fn clear(&self) {
        self.entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clear();
    }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{
            Arc, Barrier,
            atomic::{AtomicU64, Ordering},
        },
        thread,
        time::{Duration, Instant},
    };

    use crate::{
        config::{PtyTarget, Target},
        session::SessionReservation,
    };

    use super::{Clock, Identity, TicketError, TicketGenerator, TicketStore};

    struct ManualClock {
        base: Instant,
        millis: AtomicU64,
    }
    impl Clock for ManualClock {
        fn now(&self) -> Instant {
            self.base + Duration::from_millis(self.millis.load(Ordering::SeqCst))
        }
    }
    struct FixedGenerator;
    impl TicketGenerator for FixedGenerator {
        fn generate(&self) -> Result<[u8; 32], TicketError> {
            Ok([7; 32])
        }
    }
    struct SequenceGenerator(AtomicU64);
    impl TicketGenerator for SequenceGenerator {
        fn generate(&self) -> Result<[u8; 32], TicketError> {
            let mut bytes = [0_u8; 32];
            bytes[..8].copy_from_slice(&self.0.fetch_add(1, Ordering::SeqCst).to_le_bytes());
            Ok(bytes)
        }
    }
    struct ExpiringGenerator(Arc<ManualClock>);
    impl TicketGenerator for ExpiringGenerator {
        fn generate(&self) -> Result<[u8; 32], TicketError> {
            self.0.millis.store(10, Ordering::SeqCst);
            Ok([9; 32])
        }
    }

    fn controlled_store(ttl: Duration, capacity: usize) -> (TicketStore, Arc<ManualClock>) {
        let clock = Arc::new(ManualClock {
            base: Instant::now(),
            millis: AtomicU64::new(0),
        });
        let store = TicketStore::with_sources(
            ttl,
            capacity,
            clock.clone(),
            Arc::new(SequenceGenerator(AtomicU64::new(0))),
        );
        (store, clock)
    }

    fn target(name: &str) -> Target {
        Target::Pty(PtyTarget {
            name: name.to_owned(),
            executable: "/bin/sh".into(),
            argv: Vec::new(),
            read_only: false,
        })
    }

    fn reservation(identity: &Identity) -> SessionReservation {
        SessionReservation::test_reservation(identity)
    }

    #[test]
    fn tickets_are_opaque_target_bound_and_single_use() {
        let store = TicketStore::new(Duration::from_secs(10), 8);
        let alice = Identity::new("alice").unwrap();
        let ticket = store
            .issue(alice.clone(), target("shell"), reservation(&alice))
            .unwrap();
        assert_eq!(ticket.as_str().len(), 43);
        assert!(!ticket.as_str().contains("alice"));
        assert_eq!(
            store
                .redeem(ticket.as_str(), &alice)
                .unwrap()
                .target()
                .name(),
            "shell"
        );
        assert!(matches!(
            store.redeem(ticket.as_str(), &alice),
            Err(TicketError::Unknown)
        ));
    }

    #[test]
    fn wrong_identity_does_not_consume_ticket() {
        let store = TicketStore::new(Duration::from_secs(10), 8);
        let alice = Identity::new("alice").unwrap();
        let bob = Identity::new("bob").unwrap();
        let ticket = store
            .issue(alice.clone(), target("shell"), reservation(&alice))
            .unwrap();
        assert!(matches!(
            store.redeem(ticket.as_str(), &bob),
            Err(TicketError::WrongIdentity)
        ));
        assert_eq!(
            store
                .redeem(ticket.as_str(), &alice)
                .unwrap()
                .target()
                .name(),
            "shell"
        );
    }

    #[test]
    fn malformed_unknown_and_expired_tickets_have_typed_errors() {
        let (store, clock) = controlled_store(Duration::from_millis(5), 8);
        let identity = Identity::new("dev").unwrap();
        assert!(matches!(
            store.redeem("short", &identity),
            Err(TicketError::Malformed)
        ));
        assert!(matches!(
            store.redeem(&"x".repeat(10_000), &identity),
            Err(TicketError::Malformed)
        ));
        assert!(matches!(
            store.redeem(&"A".repeat(43), &identity),
            Err(TicketError::Unknown)
        ));
        let ticket = store
            .issue(identity.clone(), target("shell"), reservation(&identity))
            .unwrap();
        clock.millis.store(5, Ordering::SeqCst);
        assert!(matches!(
            store.redeem(ticket.as_str(), &identity),
            Err(TicketError::Expired)
        ));
    }

    #[test]
    fn store_capacity_is_hard_bounded_and_expiry_releases_it() {
        let (store, clock) = controlled_store(Duration::from_millis(5), 1);
        let identity = Identity::new("dev").unwrap();
        store
            .issue(identity.clone(), target("one"), reservation(&identity))
            .unwrap();
        assert_eq!(
            store.issue(identity.clone(), target("two"), reservation(&identity)),
            Err(TicketError::AtCapacity)
        );
        clock.millis.store(5, Ordering::SeqCst);
        let third_reservation = reservation(&identity);
        assert!(
            store
                .issue(identity, target("three"), third_reservation)
                .is_ok()
        );
    }

    #[test]
    fn concurrent_redemption_has_exactly_one_winner() {
        let store = Arc::new(TicketStore::new(Duration::from_secs(10), 8));
        let identity = Identity::new("dev").unwrap();
        let ticket = store
            .issue(identity.clone(), target("shell"), reservation(&identity))
            .unwrap()
            .as_str()
            .to_owned();
        let barrier = Arc::new(Barrier::new(9));
        let handles: Vec<_> = (0..8)
            .map(|_| {
                let store = Arc::clone(&store);
                let identity = identity.clone();
                let ticket = ticket.clone();
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    barrier.wait();
                    store.redeem(&ticket, &identity)
                })
            })
            .collect();
        barrier.wait();
        let successes = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .filter(Result::is_ok)
            .count();
        assert_eq!(successes, 1);
    }

    #[test]
    fn exact_ttl_boundary_and_rng_collision_are_deterministic() {
        let clock = Arc::new(ManualClock {
            base: Instant::now(),
            millis: AtomicU64::new(0),
        });
        let store = TicketStore::with_sources(
            Duration::from_millis(10),
            2,
            clock.clone(),
            Arc::new(FixedGenerator),
        );
        let identity = Identity::new("dev").unwrap();
        let ticket = store
            .issue(identity.clone(), target("shell"), reservation(&identity))
            .unwrap();
        assert_eq!(
            store.issue(identity.clone(), target("other"), reservation(&identity)),
            Err(TicketError::Generation)
        );
        clock.millis.store(10, Ordering::SeqCst);
        assert!(matches!(
            store.redeem(ticket.as_str(), &identity),
            Err(TicketError::Expired)
        ));
    }

    #[test]
    fn ticket_and_reservation_can_share_one_exact_expiry_deadline() {
        let (store, clock) = controlled_store(Duration::from_millis(10), 1);
        let identity = Identity::new("dev").unwrap();
        let expiry = store.next_expiry();
        let ticket = store
            .issue_at(
                identity.clone(),
                target("shell"),
                reservation(&identity),
                expiry,
            )
            .unwrap();

        let stored_expiry = store
            .entries
            .lock()
            .unwrap()
            .get(ticket.as_str())
            .unwrap()
            .expires_at;
        assert_eq!(stored_expiry, expiry.instant());
        clock.millis.store(10, Ordering::SeqCst);
        assert!(matches!(
            store.redeem(ticket.as_str(), &identity),
            Err(TicketError::Expired)
        ));
    }

    #[test]
    fn already_expired_shared_deadline_is_rejected_before_ticket_insertion() {
        let (store, clock) = controlled_store(Duration::from_millis(10), 1);
        let identity = Identity::new("dev").unwrap();
        let expiry = store.next_expiry();
        clock.millis.store(10, Ordering::SeqCst);

        assert!(matches!(
            store.issue_at(
                identity.clone(),
                target("shell"),
                reservation(&identity),
                expiry,
            ),
            Err(TicketError::Expired)
        ));
        assert!(store.entries.lock().unwrap().is_empty());
    }

    #[test]
    fn deadline_expiring_during_generation_is_rejected_at_insertion() {
        let clock = Arc::new(ManualClock {
            base: Instant::now(),
            millis: AtomicU64::new(0),
        });
        let store = TicketStore::with_sources(
            Duration::from_millis(10),
            1,
            clock.clone(),
            Arc::new(ExpiringGenerator(clock)),
        );
        let identity = Identity::new("dev").unwrap();
        let expiry = store.next_expiry();

        assert!(matches!(
            store.issue_at(
                identity.clone(),
                target("shell"),
                reservation(&identity),
                expiry,
            ),
            Err(TicketError::Expired)
        ));
        assert!(store.entries.lock().unwrap().is_empty());
    }
}
