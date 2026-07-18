use std::{
    collections::HashMap,
    hash::Hash,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LimitError {
    Exhausted { retry_after: Duration },
}

pub trait Clock: Send + Sync {
    fn now(&self) -> Instant;
}

struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
}

struct Bucket {
    started_at: Instant,
    generation: u64,
    count: u32,
}

struct Inner<K> {
    limit: u32,
    window: Duration,
    capacity: usize,
    clock: Arc<dyn Clock>,
    next_generation: AtomicU64,
    buckets: Mutex<HashMap<K, Bucket>>,
}

pub struct FixedWindowLimiter<K> {
    inner: Arc<Inner<K>>,
}

impl<K> FixedWindowLimiter<K>
where
    K: Clone + Eq + Hash,
{
    pub fn new(limit: u32, window: Duration, capacity: usize) -> Self {
        Self::with_clock(limit, window, capacity, Arc::new(SystemClock))
    }

    pub fn with_clock(
        limit: u32,
        window: Duration,
        capacity: usize,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            inner: Arc::new(Inner {
                limit,
                window,
                capacity,
                clock,
                next_generation: AtomicU64::new(1),
                buckets: Mutex::new(HashMap::with_capacity(capacity.min(1024))),
            }),
        }
    }

    pub fn begin(&self, key: K) -> Result<Attempt<K>, LimitError> {
        let now = self.inner.clock.now();
        let mut buckets = self
            .inner
            .buckets
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if !buckets.contains_key(&key) && buckets.len() >= self.inner.capacity {
            buckets.retain(|_, bucket| {
                now.saturating_duration_since(bucket.started_at) < self.inner.window
            });
            if buckets.len() >= self.inner.capacity {
                return Err(LimitError::Exhausted {
                    retry_after: self.inner.window,
                });
            }
        }
        let bucket = buckets.entry(key.clone()).or_insert(Bucket {
            started_at: now,
            generation: self.inner.next_generation.fetch_add(1, Ordering::Relaxed),
            count: 0,
        });
        if now.saturating_duration_since(bucket.started_at) >= self.inner.window {
            bucket.started_at = now;
            bucket.generation = self.inner.next_generation.fetch_add(1, Ordering::Relaxed);
            bucket.count = 0;
        }
        if bucket.count >= self.inner.limit {
            let elapsed = now.saturating_duration_since(bucket.started_at);
            return Err(LimitError::Exhausted {
                retry_after: self.inner.window.saturating_sub(elapsed),
            });
        }
        bucket.count += 1;
        Ok(Attempt {
            inner: Arc::clone(&self.inner),
            key: Some(key),
            generation: bucket.generation,
            committed: false,
        })
    }

    #[cfg(test)]
    fn bucket_count(&self) -> usize {
        self.inner
            .buckets
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .len()
    }
}

pub struct Attempt<K>
where
    K: Clone + Eq + Hash,
{
    inner: Arc<Inner<K>>,
    key: Option<K>,
    generation: u64,
    committed: bool,
}

impl<K> Attempt<K>
where
    K: Clone + Eq + Hash,
{
    pub fn commit(mut self) {
        self.committed = true;
    }

    pub fn rollback(mut self) {
        self.release();
        self.committed = true;
    }

    fn release(&mut self) {
        let Some(key) = self.key.take() else {
            return;
        };
        let mut buckets = self
            .inner
            .buckets
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let remove = if let Some(bucket) = buckets.get_mut(&key)
            && bucket.generation == self.generation
        {
            bucket.count = bucket.count.saturating_sub(1);
            bucket.count == 0
        } else {
            false
        };
        if remove {
            buckets.remove(&key);
        }
    }
}

impl<K> Drop for Attempt<K>
where
    K: Clone + Eq + Hash,
{
    fn drop(&mut self) {
        if !self.committed {
            self.release();
        }
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

    use super::{Clock, FixedWindowLimiter};

    struct ManualClock {
        base: Instant,
        millis: AtomicU64,
    }

    impl ManualClock {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                base: Instant::now(),
                millis: AtomicU64::new(0),
            })
        }

        fn set_millis(&self, millis: u64) {
            self.millis.store(millis, Ordering::SeqCst);
        }
    }

    impl Clock for ManualClock {
        fn now(&self) -> Instant {
            self.base + Duration::from_millis(self.millis.load(Ordering::SeqCst))
        }
    }

    #[test]
    fn fixed_window_allows_exact_first_and_last_operation() {
        let clock = ManualClock::new();
        let limiter = FixedWindowLimiter::with_clock(2, Duration::from_secs(1), 16, clock);

        limiter.begin("alice").unwrap().commit();
        limiter.begin("alice").unwrap().commit();
        assert!(limiter.begin("alice").is_err());
    }

    #[test]
    fn fixed_window_recovers_exactly_at_window_boundary() {
        let clock = ManualClock::new();
        let limiter = FixedWindowLimiter::with_clock(1, Duration::from_secs(1), 16, clock.clone());
        limiter.begin("alice").unwrap().commit();

        clock.set_millis(999);
        assert!(limiter.begin("alice").is_err());
        clock.set_millis(1_000);
        limiter.begin("alice").unwrap().commit();
    }

    #[test]
    fn many_unique_keys_never_exceed_limiter_capacity() {
        let clock = ManualClock::new();
        let limiter = FixedWindowLimiter::with_clock(1, Duration::from_secs(60), 16, clock);

        for key in 0..17 {
            let _ = limiter.begin(key).map(|attempt| attempt.commit());
        }
        assert_eq!(limiter.bucket_count(), 16);
    }

    #[test]
    fn fixed_window_rejects_first_operation_over_limit() {
        let limiter = FixedWindowLimiter::new(1, Duration::from_secs(60), 16);
        limiter.begin("alice").unwrap().commit();
        assert!(limiter.begin("alice").is_err());
    }

    #[test]
    fn fixed_window_burst_is_the_configured_allowance() {
        let limiter = FixedWindowLimiter::new(3, Duration::from_secs(60), 16);
        for _ in 0..3 {
            limiter.begin("alice").unwrap().commit();
        }
        assert!(limiter.begin("alice").is_err());
    }

    #[test]
    fn rejected_operations_do_not_consume_or_extend_the_window() {
        let clock = ManualClock::new();
        let limiter = FixedWindowLimiter::with_clock(1, Duration::from_secs(1), 16, clock.clone());
        limiter.begin("alice").unwrap().commit();
        clock.set_millis(500);
        assert!(limiter.begin("alice").is_err());
        clock.set_millis(1_000);
        limiter.begin("alice").unwrap().commit();
    }

    #[test]
    fn independent_keys_have_independent_windows() {
        let limiter = FixedWindowLimiter::new(1, Duration::from_secs(60), 16);
        limiter.begin("alice").unwrap().commit();
        limiter.begin("bob").unwrap().commit();
        assert!(limiter.begin("alice").is_err());
        assert!(limiter.begin("bob").is_err());
    }

    #[test]
    fn successful_attempt_rollback_restores_allowance() {
        let limiter = FixedWindowLimiter::new(1, Duration::from_secs(60), 16);
        limiter.begin("alice").unwrap().rollback();
        limiter.begin("alice").unwrap().commit();
    }

    #[test]
    fn rollback_from_an_old_generation_cannot_change_a_new_window() {
        let clock = ManualClock::new();
        let limiter = FixedWindowLimiter::with_clock(1, Duration::from_secs(1), 16, clock.clone());
        let old_attempt = limiter.begin("alice").unwrap();
        clock.set_millis(1_000);
        limiter.begin("alice").unwrap().commit();
        drop(old_attempt);
        assert!(limiter.begin("alice").is_err());
    }

    #[test]
    fn concurrent_attempts_have_exactly_the_configured_number_of_winners() {
        let limiter = Arc::new(FixedWindowLimiter::new(8, Duration::from_secs(60), 16));
        let barrier = Arc::new(Barrier::new(33));
        let handles = (0..32)
            .map(|_| {
                let limiter = Arc::clone(&limiter);
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    barrier.wait();
                    limiter.begin("alice").map(|attempt| attempt.commit())
                })
            })
            .collect::<Vec<_>>();
        barrier.wait();
        let winners = handles
            .into_iter()
            .map(|handle| handle.join().unwrap().is_ok())
            .filter(|winner| *winner)
            .count();
        assert_eq!(winners, 8);
    }

    #[test]
    fn stale_bucket_eviction_admits_a_new_key_at_capacity() {
        let clock = ManualClock::new();
        let limiter = FixedWindowLimiter::with_clock(1, Duration::from_secs(1), 1, clock.clone());
        limiter.begin("alice").unwrap().commit();
        clock.set_millis(1_000);
        limiter.begin("bob").unwrap().commit();
        assert_eq!(limiter.bucket_count(), 1);
    }

    #[test]
    fn full_fresh_storage_fails_closed_without_inserting_a_new_key() {
        let limiter = FixedWindowLimiter::new(1, Duration::from_secs(60), 1);
        limiter.begin("alice").unwrap().commit();
        assert!(limiter.begin("bob").is_err());
        assert_eq!(limiter.bucket_count(), 1);
    }

    #[test]
    fn retry_after_is_positive_and_exact_for_the_remaining_window() {
        let clock = ManualClock::new();
        let limiter = FixedWindowLimiter::with_clock(1, Duration::from_secs(1), 16, clock.clone());
        limiter.begin("alice").unwrap().commit();
        clock.set_millis(999);
        let retry_after = match limiter.begin("alice") {
            Err(super::LimitError::Exhausted { retry_after }) => retry_after,
            Ok(_) => panic!("the exhausted key was admitted"),
        };
        assert_eq!(retry_after, Duration::from_millis(1));
    }
}
