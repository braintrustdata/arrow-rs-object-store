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
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, RwLock};

const STALE_WHILE_REVALIDATE_ENV_VAR: &str = "OBJECT_STORE_TOKEN_CACHE_STALE_WHILE_REVALIDATE";

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
    refresh: Mutex<()>,
    min_ttl: Duration,
    fetch_backoff: Duration,
    stale_while_revalidate: bool,
}

#[derive(Debug, Clone)]
struct CacheEntry<T> {
    token: TemporaryToken<T>,
    fetched_at: Instant,
}

impl<T> Default for TokenCache<T> {
    fn default() -> Self {
        Self {
            cache: Default::default(),
            refresh: Default::default(),
            min_ttl: Duration::from_secs(300),
            // How long to wait before re-attempting a token fetch after receiving one that
            // is still within the min-ttl
            fetch_backoff: Duration::from_millis(100),
            stale_while_revalidate: std::env::var(STALE_WHILE_REVALIDATE_ENV_VAR)
                .ok()
                .and_then(|value| value.parse::<bool>().ok())
                .unwrap_or(true),
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
    fn with_stale_while_revalidate(self, stale_while_revalidate: bool) -> Self {
        Self {
            stale_while_revalidate,
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
        let cached = self.cache.read().await.clone();
        if let Some(cache) = cached.as_ref() {
            if self.is_token_valid(cache, now) {
                return Ok(cache.token.token.clone());
            }

            if self.can_use_stale_while_revalidate(cache, now) {
                if let Ok(refresh_guard) = self.refresh.try_lock() {
                    return self.refresh_and_store(refresh_guard, &f).await;
                }

                return Ok(cache.token.token.clone());
            }
        }

        let refresh_guard = self.refresh.lock().await;
        self.refresh_and_store(refresh_guard, &f).await
    }

    async fn refresh_and_store<F, Fut, E>(
        &self,
        _refresh_guard: tokio::sync::MutexGuard<'_, ()>,
        f: &F,
    ) -> Result<T, E>
    where
        F: Fn() -> Fut + Send,
        Fut: Future<Output = Result<TemporaryToken<T>, E>> + Send,
    {
        let now = Instant::now();
        let cached = self.cache.read().await.clone();
        if let Some(cache) = cached.as_ref()
            && self.is_token_valid(cache, now)
        {
            return Ok(cache.token.token.clone());
        }

        let cached = f().await?;
        let token = cached.token.clone();
        *self.cache.write().await = Some(CacheEntry {
            token: cached,
            fetched_at: Instant::now(),
        });

        Ok(token)
    }

    fn is_token_valid(&self, entry: &CacheEntry<T>, now: Instant) -> bool {
        entry.token.expiry.is_none_or(|ttl| {
            ttl.checked_duration_since(now).unwrap_or_default() > self.min_ttl
                || (entry.fetched_at.elapsed() < self.fetch_backoff && ttl > now)
        })
    }

    fn can_use_stale_while_revalidate(&self, entry: &CacheEntry<T>, now: Instant) -> bool {
        self.stale_while_revalidate && entry.token.expiry.is_some_and(|ttl| ttl > now)
    }
}

#[cfg(test)]
mod test {
    use crate::client::token::{CacheEntry, TemporaryToken, TokenCache};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::time::{Duration, Instant};
    use tokio::sync::Notify;

    // Helper function to create a token with a specific expiry duration from now
    fn create_token(token: &str, expiry_duration: Option<Duration>) -> TemporaryToken<String> {
        TemporaryToken {
            token: token.to_string(),
            expiry: expiry_duration.map(|d| Instant::now() + d),
        }
    }

    #[tokio::test]
    async fn test_expired_token_is_refreshed() {
        let cache = TokenCache::default();
        static COUNTER: AtomicU32 = AtomicU32::new(0);

        async fn get_token() -> Result<TemporaryToken<String>, String> {
            COUNTER.fetch_add(1, Ordering::SeqCst);
            Ok::<_, String>(create_token("test_token", Some(Duration::from_secs(0))))
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
        let cache = TokenCache {
            cache: Default::default(),
            refresh: Default::default(),
            min_ttl: Duration::from_secs(1),
            fetch_backoff: Duration::from_millis(1),
            stale_while_revalidate: true,
        };

        static COUNTER: AtomicU32 = AtomicU32::new(0);

        async fn get_token() -> Result<TemporaryToken<String>, String> {
            COUNTER.fetch_add(1, Ordering::SeqCst);
            Ok::<_, String>(create_token("test_token", Some(Duration::from_millis(100))))
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
    async fn test_concurrent_refresh_is_singleflight() {
        let cache = Arc::new(TokenCache::<String>::default().with_stale_while_revalidate(false));
        let counter = Arc::new(AtomicU32::new(0));

        let first = {
            let cache = cache.clone();
            let counter = counter.clone();
            tokio::spawn(async move {
                cache
                    .get_or_insert_with(|| {
                        let counter = counter.clone();
                        async move {
                            counter.fetch_add(1, Ordering::SeqCst);
                            tokio::time::sleep(Duration::from_millis(50)).await;
                            Ok::<_, String>(create_token(
                                "fresh_token",
                                Some(Duration::from_secs(60)),
                            ))
                        }
                    })
                    .await
            })
        };

        let second = {
            let cache = cache.clone();
            let counter = counter.clone();
            tokio::spawn(async move {
                cache
                    .get_or_insert_with(|| {
                        let counter = counter.clone();
                        async move {
                            counter.fetch_add(1, Ordering::SeqCst);
                            Ok::<_, String>(create_token(
                                "fresh_token",
                                Some(Duration::from_secs(60)),
                            ))
                        }
                    })
                    .await
            })
        };

        assert_eq!(first.await.unwrap().unwrap(), "fresh_token");
        assert_eq!(second.await.unwrap().unwrap(), "fresh_token");
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_stale_while_revalidate_returns_stale_token() {
        let cache = Arc::new(
            TokenCache::<String>::default()
                .with_fetch_backoff(Duration::from_millis(0))
                .with_stale_while_revalidate(true),
        );
        *cache.cache.write().await = Some(CacheEntry {
            token: create_token("stale_token", Some(Duration::from_secs(60))),
            fetched_at: Instant::now() - Duration::from_secs(301),
        });

        let refresh_started = Arc::new(Notify::new());
        let release_refresh = Arc::new(Notify::new());

        let leader = {
            let cache = cache.clone();
            let refresh_started = refresh_started.clone();
            let release_refresh = release_refresh.clone();
            tokio::spawn(async move {
                cache
                    .get_or_insert_with(|| {
                        let refresh_started = refresh_started.clone();
                        let release_refresh = release_refresh.clone();
                        async move {
                            refresh_started.notify_waiters();
                            release_refresh.notified().await;
                            Ok::<_, String>(create_token(
                                "fresh_token",
                                Some(Duration::from_secs(600)),
                            ))
                        }
                    })
                    .await
            })
        };

        refresh_started.notified().await;

        let stale = cache
            .get_or_insert_with(|| async {
                panic!("stale follower should not fetch");
                #[allow(unreachable_code)]
                Ok::<_, String>(create_token("unused", Some(Duration::from_secs(60))))
            })
            .await
            .unwrap();
        assert_eq!(stale, "stale_token");

        release_refresh.notify_waiters();
        assert_eq!(leader.await.unwrap().unwrap(), "fresh_token");
    }

    #[tokio::test]
    async fn test_disable_stale_while_revalidate_waits_for_refresh() {
        let cache = Arc::new(
            TokenCache::<String>::default()
                .with_fetch_backoff(Duration::from_millis(0))
                .with_stale_while_revalidate(false),
        );
        *cache.cache.write().await = Some(CacheEntry {
            token: create_token("stale_token", Some(Duration::from_secs(60))),
            fetched_at: Instant::now() - Duration::from_secs(301),
        });

        let refresh_started = Arc::new(Notify::new());
        let release_refresh = Arc::new(Notify::new());

        let leader = {
            let cache = cache.clone();
            let refresh_started = refresh_started.clone();
            let release_refresh = release_refresh.clone();
            tokio::spawn(async move {
                cache
                    .get_or_insert_with(|| {
                        let refresh_started = refresh_started.clone();
                        let release_refresh = release_refresh.clone();
                        async move {
                            refresh_started.notify_waiters();
                            release_refresh.notified().await;
                            Ok::<_, String>(create_token(
                                "fresh_token",
                                Some(Duration::from_secs(600)),
                            ))
                        }
                    })
                    .await
            })
        };

        refresh_started.notified().await;

        let follower = cache.get_or_insert_with(|| async {
            panic!("waiting follower should not fetch");
            #[allow(unreachable_code)]
            Ok::<_, String>(create_token("unused", Some(Duration::from_secs(60))))
        });
        tokio::pin!(follower);
        assert!(
            tokio::time::timeout(Duration::from_millis(20), &mut follower)
                .await
                .is_err()
        );

        release_refresh.notify_waiters();
        assert_eq!(follower.await.unwrap(), "fresh_token");
        assert_eq!(leader.await.unwrap().unwrap(), "fresh_token");
    }
}
