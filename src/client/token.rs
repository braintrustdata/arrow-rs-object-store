// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{info, warn};

const MAX_CACHE_AGE_ENV_VAR: &str = "OBJECT_STORE_TOKEN_CACHE_MAX_AGE_SECS";
const TOKEN_LOCK_WAIT_WARN_THRESHOLD: Duration = Duration::from_millis(100);
const TOKEN_FETCH_WARN_THRESHOLD: Duration = Duration::from_millis(100);
const TOKEN_IN_FLIGHT_WARN_INTERVAL: Duration = Duration::from_secs(5);
static NEXT_TOKEN_CACHE_ID: AtomicU64 = AtomicU64::new(1);
static NEXT_TOKEN_LOCK_WAIT_ID: AtomicU64 = AtomicU64::new(1);
static NEXT_TOKEN_LOCK_HOLDER_ID: AtomicU64 = AtomicU64::new(1);
static NEXT_REFRESH_ID: AtomicU64 = AtomicU64::new(1);

/// A temporary authentication token with an associated expiry
#[derive(Debug, Clone)]
pub(crate) struct TemporaryToken<T> {
    /// The temporary credential
    pub token: T,
    /// The instant at which this credential is no longer valid
    /// None means the credential does not expire
    pub expiry: Option<Instant>,
}

/// Provides [`TokenCache::get_or_insert_with`] which can be used to cache a
/// [`TemporaryToken`] based on its expiry
#[derive(Debug)]
pub(crate) struct TokenCache<T> {
    cache: RwLock<Option<CacheEntry<T>>>,
    min_ttl: Duration,
    fetch_backoff: Duration,
    max_cache_age: Option<Duration>,
    cache_id: u64,
    active_refresh_id: AtomicU64,
    active_refresh_blocked_readers: AtomicU64,
    active_write_waiters: AtomicU64,
    active_read_holders: AtomicU64,
    active_write_holder_id: AtomicU64,
    active_write_holder_refresh_id: AtomicU64,
}

#[derive(Debug)]
struct CacheEntry<T> {
    token: TemporaryToken<T>,
    fetched_at: Instant,
}

struct ReadLockHolder<'a> {
    cache_id: u64,
    holder_id: u64,
    acquired_at: Instant,
    active_read_holders: &'a AtomicU64,
    active_write_waiters: &'a AtomicU64,
    active_write_holder_id: &'a AtomicU64,
}

impl<'a> ReadLockHolder<'a> {
    fn new(cache: &'a TokenCache<impl Clone + Send + Sync>) -> Self {
        let holder_id = NEXT_TOKEN_LOCK_HOLDER_ID.fetch_add(1, Ordering::Relaxed);
        cache.active_read_holders.fetch_add(1, Ordering::Relaxed);
        Self {
            cache_id: cache.cache_id,
            holder_id,
            acquired_at: Instant::now(),
            active_read_holders: &cache.active_read_holders,
            active_write_waiters: &cache.active_write_waiters,
            active_write_holder_id: &cache.active_write_holder_id,
        }
    }

    fn log_acquired(&self, read_wait_elapsed: Duration) {
        info!(
            cache_id = self.cache_id,
            holder_id = self.holder_id,
            wait_ms = read_wait_elapsed.as_millis(),
            active_read_holders = self.active_read_holders.load(Ordering::Relaxed),
            waiting_writers = self.active_write_waiters.load(Ordering::Relaxed),
            active_write_holder_id = self.active_write_holder_id.load(Ordering::Relaxed),
            "token cache read lock acquired after long wait"
        );
    }
}

impl Drop for ReadLockHolder<'_> {
    fn drop(&mut self) {
        let remaining_read_holders = self.active_read_holders.fetch_sub(1, Ordering::Relaxed) - 1;
        let hold_elapsed = self.acquired_at.elapsed();
        if hold_elapsed >= TOKEN_LOCK_WAIT_WARN_THRESHOLD {
            warn!(
                cache_id = self.cache_id,
                holder_id = self.holder_id,
                hold_ms = hold_elapsed.as_millis(),
                remaining_read_holders,
                waiting_writers = self.active_write_waiters.load(Ordering::Relaxed),
                active_write_holder_id = self.active_write_holder_id.load(Ordering::Relaxed),
                "token cache read lock released after long hold"
            );
        }
    }
}

struct WriteLockHolder<'a> {
    cache_id: u64,
    holder_id: u64,
    acquired_at: Instant,
    active_write_holder_id: &'a AtomicU64,
    active_write_holder_refresh_id: &'a AtomicU64,
    active_read_holders: &'a AtomicU64,
}

impl<'a> WriteLockHolder<'a> {
    fn new(cache: &'a TokenCache<impl Clone + Send + Sync>) -> Self {
        let holder_id = NEXT_TOKEN_LOCK_HOLDER_ID.fetch_add(1, Ordering::Relaxed);
        cache.active_write_holder_id.store(holder_id, Ordering::Relaxed);
        cache.active_write_holder_refresh_id.store(0, Ordering::Relaxed);
        info!(
            cache_id = cache.cache_id,
            holder_id,
            active_read_holders = cache.active_read_holders.load(Ordering::Relaxed),
            waiting_writers = cache.active_write_waiters.load(Ordering::Relaxed),
            "token cache write lock acquired"
        );
        Self {
            cache_id: cache.cache_id,
            holder_id,
            acquired_at: Instant::now(),
            active_write_holder_id: &cache.active_write_holder_id,
            active_write_holder_refresh_id: &cache.active_write_holder_refresh_id,
            active_read_holders: &cache.active_read_holders,
        }
    }
}

impl Drop for WriteLockHolder<'_> {
    fn drop(&mut self) {
        let hold_elapsed = self.acquired_at.elapsed();
        warn!(
            cache_id = self.cache_id,
            holder_id = self.holder_id,
            refresh_id = self.active_write_holder_refresh_id.load(Ordering::Relaxed),
            hold_ms = hold_elapsed.as_millis(),
            active_read_holders = self.active_read_holders.load(Ordering::Relaxed),
            "token cache write lock released"
        );
        self.active_write_holder_id.store(0, Ordering::Relaxed);
        self.active_write_holder_refresh_id.store(0, Ordering::Relaxed);
    }
}

#[derive(Clone, Copy, Debug)]
enum RefreshReason {
    Empty,
    MaxCacheAge,
    Expired,
    MinTtl,
}

impl RefreshReason {
    fn as_str(self) -> &'static str {
        match self {
            Self::Empty => "empty-cache",
            Self::MaxCacheAge => "max-cache-age",
            Self::Expired => "expired",
            Self::MinTtl => "min-ttl",
        }
    }
}

impl<T> Default for TokenCache<T> {
    fn default() -> Self {
        let max_cache_age = std::env::var(MAX_CACHE_AGE_ENV_VAR)
            .ok()
            .and_then(|value| match value.parse::<u64>() {
                Ok(seconds) => Some(Duration::from_secs(seconds)),
                Err(error) => {
                    warn!(
                        env_var = MAX_CACHE_AGE_ENV_VAR,
                        value,
                        %error,
                        "failed to parse token cache max age override"
                    );
                    None
                }
            });
        if let Some(max_cache_age) = max_cache_age {
            warn!(
                env_var = MAX_CACHE_AGE_ENV_VAR,
                max_cache_age_s = max_cache_age.as_secs(),
                "token cache max age override enabled"
            );
        }
        Self {
            cache: Default::default(),
            min_ttl: Duration::from_secs(300),
            // How long to wait before re-attempting a token fetch after receiving one that
            // is still within the min-ttl
            fetch_backoff: Duration::from_millis(100),
            max_cache_age,
            cache_id: NEXT_TOKEN_CACHE_ID.fetch_add(1, Ordering::Relaxed),
            active_refresh_id: AtomicU64::new(0),
            active_refresh_blocked_readers: AtomicU64::new(0),
            active_write_waiters: AtomicU64::new(0),
            active_read_holders: AtomicU64::new(0),
            active_write_holder_id: AtomicU64::new(0),
            active_write_holder_refresh_id: AtomicU64::new(0),
        }
    }
}

impl<T: Clone + Send + Sync> TokenCache<T> {
    /// Override the minimum remaining TTL for a cached token to be used
    #[cfg(any(feature = "aws", feature = "gcp"))]
    pub(crate) fn with_min_ttl(self, min_ttl: Duration) -> Self {
        Self { min_ttl, ..self }
    }

    #[cfg(test)]
    fn with_max_cache_age(self, max_cache_age: Option<Duration>) -> Self {
        Self {
            max_cache_age,
            ..self
        }
    }

    #[cfg(test)]
    fn with_fetch_backoff(self, fetch_backoff: Duration) -> Self {
        Self {
            fetch_backoff,
            ..self
        }
    }

    pub(crate) async fn get_or_insert_with<F, Fut, E>(&self, f: F) -> Result<T, E>
    where
        F: FnOnce() -> Fut + Send,
        Fut: Future<Output = Result<TemporaryToken<T>, E>> + Send,
    {
        let now = Instant::now();
        let read_wait_start = Instant::now();
        let read_wait_id = NEXT_TOKEN_LOCK_WAIT_ID.fetch_add(1, Ordering::Relaxed);
        let read_guard = self
            .await_with_periodic_warn(self.cache.read(), |elapsed| {
                warn!(
                    cache_id = self.cache_id,
                    wait_id = read_wait_id,
                    refresh_id = self.active_refresh_id.load(Ordering::Relaxed),
                    blocked_reader_count =
                        self.active_refresh_blocked_readers.load(Ordering::Relaxed),
                    waiting_writers = self.active_write_waiters.load(Ordering::Relaxed),
                    active_read_holders = self.active_read_holders.load(Ordering::Relaxed),
                    active_write_holder_id = self.active_write_holder_id.load(Ordering::Relaxed),
                    elapsed_ms = elapsed.as_millis(),
                    "token cache read lock wait still in flight"
                );
            })
            .await;
        let read_holder = ReadLockHolder::new(self);
        let read_wait_elapsed = read_wait_start.elapsed();
        if read_wait_elapsed > TOKEN_LOCK_WAIT_WARN_THRESHOLD {
            let refresh_id = self.active_refresh_id.load(Ordering::Relaxed);
            let blocked_reader_count = if refresh_id == 0 {
                0
            } else {
                self.active_refresh_blocked_readers
                    .fetch_add(1, Ordering::Relaxed)
                    + 1
            };
            warn!(
                cache_id = self.cache_id,
                refresh_id,
                blocked_reader_count,
                waiting_writers = self.active_write_waiters.load(Ordering::Relaxed),
                active_read_holders = self.active_read_holders.load(Ordering::Relaxed),
                active_write_holder_id = self.active_write_holder_id.load(Ordering::Relaxed),
                wait_ms = read_wait_elapsed.as_millis(),
                "waited for token cache read lock"
            );
        }
        if read_wait_elapsed >= TOKEN_LOCK_WAIT_WARN_THRESHOLD {
            read_holder.log_acquired(read_wait_elapsed);
        }
        if let Some(cache) = read_guard.as_ref()
            && self.is_token_valid(cache, now)
        {
            return Ok(cache.token.token.clone());
        }
        drop(read_guard);

        let write_wait_start = Instant::now();
        let write_wait_id = NEXT_TOKEN_LOCK_WAIT_ID.fetch_add(1, Ordering::Relaxed);
        self.active_write_waiters.fetch_add(1, Ordering::Relaxed);
        let mut guard = self
            .await_with_periodic_warn(self.cache.write(), |elapsed| {
                warn!(
                    cache_id = self.cache_id,
                    wait_id = write_wait_id,
                    refresh_id = self.active_refresh_id.load(Ordering::Relaxed),
                    waiting_writers = self.active_write_waiters.load(Ordering::Relaxed),
                    active_read_holders = self.active_read_holders.load(Ordering::Relaxed),
                    active_write_holder_id = self.active_write_holder_id.load(Ordering::Relaxed),
                    elapsed_ms = elapsed.as_millis(),
                    "token cache write lock wait still in flight"
                );
            })
            .await;
        self.active_write_waiters.fetch_sub(1, Ordering::Relaxed);
        let _write_holder = WriteLockHolder::new(self);
        let write_wait_elapsed = write_wait_start.elapsed();
        if write_wait_elapsed > TOKEN_LOCK_WAIT_WARN_THRESHOLD {
            warn!(
                cache_id = self.cache_id,
                waiting_writers = self.active_write_waiters.load(Ordering::Relaxed),
                active_read_holders = self.active_read_holders.load(Ordering::Relaxed),
                active_write_holder_id = self.active_write_holder_id.load(Ordering::Relaxed),
                wait_ms = write_wait_elapsed.as_millis(),
                "waited for token cache write lock"
            );
        }
        if write_wait_elapsed >= TOKEN_IN_FLIGHT_WARN_INTERVAL {
            info!(
                cache_id = self.cache_id,
                wait_id = write_wait_id,
                refresh_id = self.active_refresh_id.load(Ordering::Relaxed),
                wait_ms = write_wait_elapsed.as_millis(),
                "token cache write lock acquired after long wait"
            );
        }

        if let Some(cache) = guard.as_ref()
            && self.is_token_valid(cache, now)
        {
            return Ok(cache.token.token.clone());
        }

        let refresh_reason = self.refresh_reason(guard.as_ref(), now);
        let refresh_id = NEXT_REFRESH_ID.fetch_add(1, Ordering::Relaxed);
        self.active_refresh_blocked_readers
            .store(0, Ordering::Relaxed);
        self.active_refresh_id.store(refresh_id, Ordering::Relaxed);
        self.active_write_holder_refresh_id
            .store(refresh_id, Ordering::Relaxed);
        info!(
            cache_id = self.cache_id,
            write_holder_id = self.active_write_holder_id.load(Ordering::Relaxed),
            refresh_id,
            reason = refresh_reason.as_str(),
            cached_age_ms = guard
                .as_ref()
                .map(|entry| entry.fetched_at.elapsed().as_millis()),
            cached_ttl_remaining_ms = guard
                .as_ref()
                .and_then(|entry| entry.token.expiry)
                .map(|expiry| {
                    expiry
                        .checked_duration_since(now)
                        .unwrap_or_default()
                        .as_millis()
                }),
            holding_cache_write_lock = true,
            "starting temporary credential refresh"
        );
        let fetch_start = Instant::now();
        let fetched = self
            .await_with_periodic_warn(f(), |elapsed| {
                warn!(
                    cache_id = self.cache_id,
                    refresh_id,
                    reason = refresh_reason.as_str(),
                    blocked_reader_count =
                        self.active_refresh_blocked_readers.load(Ordering::Relaxed),
                    waiting_writers = self.active_write_waiters.load(Ordering::Relaxed),
                    active_read_holders = self.active_read_holders.load(Ordering::Relaxed),
                    active_write_holder_id = self.active_write_holder_id.load(Ordering::Relaxed),
                    holding_cache_write_lock = true,
                    elapsed_ms = elapsed.as_millis(),
                    "temporary credential fetch still in flight"
                );
            })
            .await;
        let fetch_elapsed = fetch_start.elapsed();
        let blocked_reader_count = self
            .active_refresh_blocked_readers
            .swap(0, Ordering::Relaxed);
        self.active_refresh_id.store(0, Ordering::Relaxed);
        if fetch_elapsed > TOKEN_FETCH_WARN_THRESHOLD || blocked_reader_count > 0 {
            warn!(
                cache_id = self.cache_id,
                refresh_id,
                reason = refresh_reason.as_str(),
                fetch_ms = fetch_elapsed.as_millis(),
                success = fetched.is_ok(),
                blocked_reader_count,
                waiting_writers = self.active_write_waiters.load(Ordering::Relaxed),
                active_read_holders = self.active_read_holders.load(Ordering::Relaxed),
                active_write_holder_id = self.active_write_holder_id.load(Ordering::Relaxed),
                holding_cache_write_lock = true,
                "temporary credential fetch finished"
            );
        }
        let cached = fetched?;
        let token = cached.token.clone();
        *guard = Some(CacheEntry {
            token: cached,
            fetched_at: Instant::now(),
        });
        Ok(token)
    }

    fn is_token_valid(&self, entry: &CacheEntry<T>, now: Instant) -> bool {
        if self
            .max_cache_age
            .is_some_and(|max_cache_age| entry.fetched_at.elapsed() > max_cache_age)
        {
            return false;
        }
        entry.token.expiry.is_none_or(|ttl| {
            ttl.checked_duration_since(now).unwrap_or_default() > self.min_ttl ||
            (entry.fetched_at.elapsed() < self.fetch_backoff && ttl > now)
        })
    }

    fn refresh_reason(&self, entry: Option<&CacheEntry<T>>, now: Instant) -> RefreshReason {
        let Some(entry) = entry else {
            return RefreshReason::Empty;
        };
        if self
            .max_cache_age
            .is_some_and(|max_cache_age| entry.fetched_at.elapsed() > max_cache_age)
        {
            return RefreshReason::MaxCacheAge;
        }
        if entry.token.expiry.is_some_and(|expiry| expiry <= now) {
            return RefreshReason::Expired;
        }
        RefreshReason::MinTtl
    }

    async fn await_with_periodic_warn<F, O, L>(&self, future: F, mut log: L) -> O
    where
        F: Future<Output = O>,
        L: FnMut(Duration),
    {
        #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
        {
            future.await
        }

        #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
        {
            let start = Instant::now();
            tokio::pin!(future);
            loop {
                tokio::select! {
                    output = &mut future => return output,
                    _ = tokio::time::sleep(TOKEN_IN_FLIGHT_WARN_INTERVAL) => {
                        log(start.elapsed());
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod test {
    use crate::client::token::{TemporaryToken, TokenCache};
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::time::{Duration, Instant};

    // Helper function to create a token with a specific expiry duration from now
    fn create_token(expiry_duration: Option<Duration>) -> TemporaryToken<String> {
        TemporaryToken {
            token: "test_token".to_string(),
            expiry: expiry_duration.map(|d| Instant::now() + d),
        }
    }

    #[tokio::test]
    async fn test_expired_token_is_refreshed() {
        let cache = TokenCache::default();
        static COUNTER: AtomicU32 = AtomicU32::new(0);

        async fn get_token() -> Result<TemporaryToken<String>, String> {
            COUNTER.fetch_add(1, Ordering::SeqCst);
            Ok::<_, String>(create_token(Some(Duration::from_secs(0))))
        }

        // Should fetch initial token
        let _ = cache.get_or_insert_with(get_token).await.unwrap();
        assert_eq!(COUNTER.load(Ordering::SeqCst), 1);

        tokio::time::sleep(Duration::from_millis(2)).await;

        // Token is expired, so should fetch again
        let _ = cache.get_or_insert_with(get_token).await.unwrap();
        assert_eq!(COUNTER.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn test_min_ttl_causes_refresh() {
        let cache = TokenCache::default()
            .with_min_ttl(Duration::from_secs(1))
            .with_fetch_backoff(Duration::from_millis(1));

        static COUNTER: AtomicU32 = AtomicU32::new(0);

        async fn get_token() -> Result<TemporaryToken<String>, String> {
            COUNTER.fetch_add(1, Ordering::SeqCst);
            Ok::<_, String>(create_token(Some(Duration::from_millis(100))))
        }

        // Initial fetch
        let _ = cache.get_or_insert_with(get_token).await.unwrap();
        assert_eq!(COUNTER.load(Ordering::SeqCst), 1);

        // Should not fetch again since not expired and within fetch_backoff
        let _ = cache.get_or_insert_with(get_token).await.unwrap();
        assert_eq!(COUNTER.load(Ordering::SeqCst), 1);

        tokio::time::sleep(Duration::from_millis(2)).await;

        // Should fetch, since we've passed fetch_backoff
        let _ = cache.get_or_insert_with(get_token).await.unwrap();
        assert_eq!(COUNTER.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn test_max_cache_age_forces_refresh() {
        let cache = TokenCache::default().with_max_cache_age(Some(Duration::from_millis(10)));
        static COUNTER: AtomicU32 = AtomicU32::new(0);

        async fn get_token() -> Result<TemporaryToken<String>, String> {
            COUNTER.fetch_add(1, Ordering::SeqCst);
            Ok::<_, String>(create_token(Some(Duration::from_secs(3600))))
        }

        let _ = cache.get_or_insert_with(get_token).await.unwrap();
        assert_eq!(COUNTER.load(Ordering::SeqCst), 1);

        tokio::time::sleep(Duration::from_millis(15)).await;

        let _ = cache.get_or_insert_with(get_token).await.unwrap();
        assert_eq!(COUNTER.load(Ordering::SeqCst), 2);
    }
}
