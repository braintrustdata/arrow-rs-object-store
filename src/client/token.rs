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

use arc_swap::ArcSwapOption;
use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
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
    cache: ArcSwapOption<CacheEntry<T>>,
    refresh_lock: Mutex<()>,
    min_ttl: Duration,
    fetch_backoff: Duration,
    max_cache_age: Option<Duration>,
    cache_id: u64,
    active_refresh_id: AtomicU64,
    active_refresh_waiters: AtomicU64,
    active_refresh_holder_id: AtomicU64,
}

#[derive(Debug)]
struct CacheEntry<T> {
    token: TemporaryToken<T>,
    fetched_at: Instant,
}

struct RefreshLockHolder<'a> {
    cache_id: u64,
    holder_id: u64,
    acquired_at: Instant,
    active_refresh_holder_id: &'a AtomicU64,
    active_refresh_id: &'a AtomicU64,
    active_refresh_waiters: &'a AtomicU64,
}

impl<'a> RefreshLockHolder<'a> {
    fn new(cache: &'a TokenCache<impl Clone + Send + Sync>) -> Self {
        let holder_id = NEXT_TOKEN_LOCK_HOLDER_ID.fetch_add(1, Ordering::Relaxed);
        cache
            .active_refresh_holder_id
            .store(holder_id, Ordering::Relaxed);
        info!(
            cache_id = cache.cache_id,
            holder_id,
            waiting_refreshers = cache.active_refresh_waiters.load(Ordering::Relaxed),
            active_refresh_id = cache.active_refresh_id.load(Ordering::Relaxed),
            "token cache refresh gate acquired"
        );
        Self {
            cache_id: cache.cache_id,
            holder_id,
            acquired_at: Instant::now(),
            active_refresh_holder_id: &cache.active_refresh_holder_id,
            active_refresh_id: &cache.active_refresh_id,
            active_refresh_waiters: &cache.active_refresh_waiters,
        }
    }
}

impl Drop for RefreshLockHolder<'_> {
    fn drop(&mut self) {
        let hold_elapsed = self.acquired_at.elapsed();
        warn!(
            cache_id = self.cache_id,
            holder_id = self.holder_id,
            refresh_id = self.active_refresh_id.load(Ordering::Relaxed),
            hold_ms = hold_elapsed.as_millis(),
            waiting_refreshers = self.active_refresh_waiters.load(Ordering::Relaxed),
            "token cache refresh gate released"
        );
        self.active_refresh_holder_id.store(0, Ordering::Relaxed);
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
            cache: ArcSwapOption::new(None),
            refresh_lock: Default::default(),
            min_ttl: Duration::from_secs(300),
            fetch_backoff: Duration::from_millis(100),
            max_cache_age,
            cache_id: NEXT_TOKEN_CACHE_ID.fetch_add(1, Ordering::Relaxed),
            active_refresh_id: AtomicU64::new(0),
            active_refresh_waiters: AtomicU64::new(0),
            active_refresh_holder_id: AtomicU64::new(0),
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
        F: Fn() -> Fut + Send,
        Fut: Future<Output = Result<TemporaryToken<T>, E>> + Send,
    {
        let now = Instant::now();
        if let Some(token) = self.try_get_cached(now) {
            return Ok(token);
        }

        let refresh_wait_start = Instant::now();
        let refresh_wait_id = NEXT_TOKEN_LOCK_WAIT_ID.fetch_add(1, Ordering::Relaxed);
        self.active_refresh_waiters.fetch_add(1, Ordering::Relaxed);
        let refresh_guard = self
            .await_with_periodic_warn(self.refresh_lock.lock(), |elapsed| {
                warn!(
                    cache_id = self.cache_id,
                    wait_id = refresh_wait_id,
                    refresh_id = self.active_refresh_id.load(Ordering::Relaxed),
                    waiting_refreshers = self.active_refresh_waiters.load(Ordering::Relaxed),
                    active_refresh_holder_id =
                        self.active_refresh_holder_id.load(Ordering::Relaxed),
                    elapsed_ms = elapsed.as_millis(),
                    "token cache refresh wait still in flight"
                );
            })
            .await;
        self.active_refresh_waiters.fetch_sub(1, Ordering::Relaxed);
        let _refresh_guard = refresh_guard;
        let _refresh_holder = RefreshLockHolder::new(self);
        let refresh_wait_elapsed = refresh_wait_start.elapsed();
        if refresh_wait_elapsed > TOKEN_LOCK_WAIT_WARN_THRESHOLD {
            warn!(
                cache_id = self.cache_id,
                refresh_id = self.active_refresh_id.load(Ordering::Relaxed),
                waiting_refreshers = self.active_refresh_waiters.load(Ordering::Relaxed),
                active_refresh_holder_id = self.active_refresh_holder_id.load(Ordering::Relaxed),
                wait_ms = refresh_wait_elapsed.as_millis(),
                "waited for token cache refresh gate"
            );
        }
        if refresh_wait_elapsed >= TOKEN_IN_FLIGHT_WARN_INTERVAL {
            info!(
                cache_id = self.cache_id,
                wait_id = refresh_wait_id,
                refresh_id = self.active_refresh_id.load(Ordering::Relaxed),
                wait_ms = refresh_wait_elapsed.as_millis(),
                "token cache refresh gate acquired after long wait"
            );
        }

        let now = Instant::now();
        let cache_entry = self.cache.load_full();
        if let Some(cache) = cache_entry.as_deref()
            && self.is_token_valid(cache, now)
        {
            return Ok(cache.token.token.clone());
        }

        let refresh_reason = self.refresh_reason(cache_entry.as_deref(), now);
        let refresh_id = NEXT_REFRESH_ID.fetch_add(1, Ordering::Relaxed);
        self.active_refresh_id.store(refresh_id, Ordering::Relaxed);
        info!(
            cache_id = self.cache_id,
            refresh_holder_id = self.active_refresh_holder_id.load(Ordering::Relaxed),
            refresh_id,
            reason = refresh_reason.as_str(),
            cached_age_ms = cache_entry
                .as_ref()
                .map(|entry| entry.fetched_at.elapsed().as_millis()),
            cached_ttl_remaining_ms = cache_entry
                .as_ref()
                .and_then(|entry| entry.token.expiry)
                .map(|expiry| {
                    expiry
                        .checked_duration_since(now)
                        .unwrap_or_default()
                        .as_millis()
                }),
            "starting temporary credential refresh"
        );

        let fetch_start = Instant::now();
        let fetched = self
            .await_with_periodic_warn(f(), |elapsed| {
                warn!(
                    cache_id = self.cache_id,
                    refresh_id,
                    reason = refresh_reason.as_str(),
                    waiting_refreshers = self.active_refresh_waiters.load(Ordering::Relaxed),
                    active_refresh_holder_id =
                        self.active_refresh_holder_id.load(Ordering::Relaxed),
                    elapsed_ms = elapsed.as_millis(),
                    "temporary credential fetch still in flight"
                );
            })
            .await;
        let fetch_elapsed = fetch_start.elapsed();
        if fetch_elapsed > TOKEN_FETCH_WARN_THRESHOLD
            || self.active_refresh_waiters.load(Ordering::Relaxed) > 0
        {
            warn!(
                cache_id = self.cache_id,
                refresh_id,
                reason = refresh_reason.as_str(),
                fetch_ms = fetch_elapsed.as_millis(),
                success = fetched.is_ok(),
                waiting_refreshers = self.active_refresh_waiters.load(Ordering::Relaxed),
                active_refresh_holder_id = self.active_refresh_holder_id.load(Ordering::Relaxed),
                "temporary credential fetch finished"
            );
        }

        let cached = match fetched {
            Ok(cached) => cached,
            Err(error) => {
                self.active_refresh_id.store(0, Ordering::Relaxed);
                return Err(error);
            }
        };
        let token = cached.token.clone();
        self.cache.store(Some(Arc::new(CacheEntry {
            token: cached,
            fetched_at: Instant::now(),
        })));
        self.active_refresh_id.store(0, Ordering::Relaxed);
        Ok(token)
    }

    fn try_get_cached(&self, now: Instant) -> Option<T> {
        let entry = self.cache.load_full()?;
        self.is_token_valid(entry.as_ref(), now)
            .then(|| entry.token.token.clone())
    }

    fn is_token_valid(&self, entry: &CacheEntry<T>, now: Instant) -> bool {
        if self
            .max_cache_age
            .is_some_and(|max_cache_age| entry.fetched_at.elapsed() > max_cache_age)
        {
            return false;
        }
        entry.token.expiry.is_none_or(|ttl| {
            ttl.checked_duration_since(now).unwrap_or_default() > self.min_ttl
                || (entry.fetched_at.elapsed() < self.fetch_backoff && ttl > now)
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
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::time::{Duration, Instant};
    use tokio::sync::Barrier;

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

        let _ = cache.get_or_insert_with(get_token).await.unwrap();
        assert_eq!(COUNTER.load(Ordering::SeqCst), 1);

        tokio::time::sleep(Duration::from_millis(2)).await;

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

        let _ = cache.get_or_insert_with(get_token).await.unwrap();
        assert_eq!(COUNTER.load(Ordering::SeqCst), 1);

        let _ = cache.get_or_insert_with(get_token).await.unwrap();
        assert_eq!(COUNTER.load(Ordering::SeqCst), 1);

        tokio::time::sleep(Duration::from_millis(2)).await;

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

    #[tokio::test]
    async fn test_concurrent_refresh_is_singleflight() {
        let cache = Arc::new(TokenCache::default());
        let barrier = Arc::new(Barrier::new(8));
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        COUNTER.store(0, Ordering::SeqCst);

        let tasks = (0..8)
            .map(|_| {
                let cache = Arc::clone(&cache);
                let barrier = Arc::clone(&barrier);
                tokio::spawn(async move {
                    barrier.wait().await;
                    cache
                        .get_or_insert_with(|| async {
                            COUNTER.fetch_add(1, Ordering::SeqCst);
                            tokio::time::sleep(Duration::from_millis(25)).await;
                            Ok::<_, String>(create_token(Some(Duration::from_secs(3600))))
                        })
                        .await
                })
            })
            .collect::<Vec<_>>();

        for task in tasks {
            task.await.unwrap().unwrap();
        }

        assert_eq!(COUNTER.load(Ordering::SeqCst), 1);
    }
}
