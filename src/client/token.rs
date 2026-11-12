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
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

const TOKEN_REFRESH_TIMEOUT: Duration = Duration::from_secs(120);

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
    cache: Arc<RwLock<Option<CacheEntry<T>>>>,
    min_ttl: Duration,
    fetch_backoff: Duration,
}

#[derive(Debug)]
struct CacheEntry<T> {
    token: TemporaryToken<T>,
    fetched_at: Instant,
}

impl<T> Default for TokenCache<T> {
    fn default() -> Self {
        Self {
            cache: Default::default(),
            min_ttl: Duration::from_secs(300),
            // How long to wait before re-attempting a token fetch after receiving one that
            // is still within the min-ttl
            fetch_backoff: Duration::from_millis(100),
        }
    }
}

impl<T: Clone + Send + Sync + 'static> TokenCache<T> {
    /// Override the minimum remaining TTL for a cached token to be used
    #[cfg(any(feature = "aws", feature = "gcp"))]
    pub(crate) fn with_min_ttl(self, min_ttl: Duration) -> Self {
        Self { min_ttl, ..self }
    }

    pub(crate) async fn get_or_insert_with<F, Fut, E>(&self, f: F) -> Result<T, E>
    where
        F: FnOnce() -> Fut + Send,
        Fut: Future<Output = Result<TemporaryToken<T>, E>> + Send + 'static,
        E: From<crate::Error> + Send + 'static,
    {
        let now = Instant::now();
        let is_token_valid = |entry: &CacheEntry<T>| {
            entry.token.expiry.is_none_or(|ttl| {
                ttl.checked_duration_since(now).unwrap_or_default() > self.min_ttl ||
                // if we've recently attempted to fetch this token and it's not actually
                // expired, we'll wait to re-fetch it and return the cached one
                (entry.fetched_at.elapsed() < self.fetch_backoff && ttl > now)
            })
        };

        if let Some(cache) = self.cache.read().await.as_ref()
            && is_token_valid(cache)
        {
            return Ok(cache.token.token.clone());
        }

        let mut guard = Arc::clone(&self.cache).write_owned().await;
        if let Some(cache) = guard.as_ref()
            && is_token_valid(cache)
        {
            // Refresh race
            return Ok(cache.token.token.clone());
        }

        let fetch = f();
        let refresh = async move {
            let cached = tokio::time::timeout(TOKEN_REFRESH_TIMEOUT, fetch)
                .await
                .map_err(|source| crate::Error::Generic {
                    store: "TokenCache",
                    source: Box::new(source),
                })??;
            let token = cached.token.clone();
            *guard = Some(CacheEntry {
                token: cached,
                fetched_at: Instant::now(),
            });
            Ok(token)
        };
        #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
        {
            tokio::spawn(refresh).await.map_err(crate::Error::from)?
        }
        #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
        {
            let (send, receive) = tokio::sync::oneshot::channel();
            wasm_bindgen_futures::spawn_local(async move {
                let _ = send.send(refresh.await);
            });
            receive.await.map_err(|source| crate::Error::Generic {
                store: "TokenCache",
                source: Box::new(source),
            })?
        }
    }
}

#[cfg(test)]
mod test {
    use crate::client::token::{TemporaryToken, TokenCache};
    use futures_util::FutureExt;
    use std::sync::Arc;
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

        async fn get_token() -> crate::Result<TemporaryToken<String>> {
            COUNTER.fetch_add(1, Ordering::SeqCst);
            Ok::<_, crate::Error>(create_token(Some(Duration::from_secs(0))))
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
            min_ttl: Duration::from_secs(1),
            fetch_backoff: Duration::from_millis(1),
        };

        static COUNTER: AtomicU32 = AtomicU32::new(0);

        async fn get_token() -> crate::Result<TemporaryToken<String>> {
            COUNTER.fetch_add(1, Ordering::SeqCst);
            Ok::<_, crate::Error>(create_token(Some(Duration::from_millis(100))))
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

    async fn refresh_survives_suspended_request(drop_request: bool) {
        let cache = Arc::new(TokenCache::<String>::default());
        let (started, started_wait) = tokio::sync::oneshot::channel();
        let (response, response_wait) = tokio::sync::oneshot::channel();
        let mut request = Box::pin(cache.get_or_insert_with(|| async move {
            started.send(()).unwrap();
            response_wait.await.unwrap();
            Ok::<_, crate::Error>(create_token(None))
        }));
        assert!(request.as_mut().now_or_never().is_none());
        tokio::time::timeout(Duration::from_secs(2), started_wait)
            .await
            .unwrap()
            .unwrap();
        assert!(cache.cache.try_read().is_err());
        let mut request = if drop_request {
            drop(request);
            None
        } else {
            Some(request)
        };
        response.send(()).unwrap();
        let token = tokio::time::timeout(
            Duration::from_secs(2),
            cache.get_or_insert_with(|| async {
                panic!("concurrent request must reuse the in-flight refresh");
                #[allow(unreachable_code)]
                Ok::<_, crate::Error>(create_token(None))
            }),
        )
        .await
        .expect("suspended request blocked credential refresh")
        .unwrap();
        assert_eq!(token, "test_token");
        if let Some(request) = request.as_mut() {
            assert_eq!(request.await.unwrap(), "test_token");
        }
    }

    #[tokio::test]
    async fn test_refresh_completes_without_polling_request() {
        refresh_survives_suspended_request(false).await;
    }

    #[tokio::test]
    async fn test_refresh_completes_after_request_is_dropped() {
        refresh_survives_suspended_request(true).await;
    }

    async fn refresh_timeout_releases_cache(drop_request: bool) {
        let cache = TokenCache::<String>::default();
        let (started, started_wait) = tokio::sync::oneshot::channel();
        let (cancelled_wait, cancelled) = tokio::sync::oneshot::channel::<()>();
        let mut request = Box::pin(cache.get_or_insert_with(|| async move {
            started.send(()).unwrap();
            cancelled.await.unwrap();
            Ok::<_, crate::Error>(create_token(None))
        }));
        assert!(request.as_mut().now_or_never().is_none());
        started_wait.await.unwrap();
        assert!(cache.cache.try_read().is_err());
        let mut request = if drop_request {
            drop(request);
            None
        } else {
            Some(request)
        };
        tokio::time::advance(Duration::from_secs(121)).await;
        tokio::task::yield_now().await;
        assert!(
            cancelled_wait.is_closed(),
            "timed-out fetch was not dropped"
        );
        assert!(cache.cache.try_read().unwrap().is_none());
        if let Some(request) = request.as_mut() {
            let err = request.await.unwrap_err();
            assert!(err.to_string().contains("deadline has elapsed"));
        }
        let token = cache
            .get_or_insert_with(|| async { Ok::<_, crate::Error>(create_token(None)) })
            .await
            .unwrap();
        assert_eq!(token, "test_token");
    }

    #[tokio::test(start_paused = true)]
    async fn test_refresh_times_out_without_polling_request() {
        refresh_timeout_releases_cache(false).await;
    }

    #[tokio::test(start_paused = true)]
    async fn test_refresh_times_out_after_request_is_dropped() {
        refresh_timeout_releases_cache(true).await;
    }

    #[tokio::test]
    async fn test_refresh_failure_releases_cache() {
        let cache = TokenCache::<String>::default();
        let err = cache
            .get_or_insert_with(|| async {
                Err::<TemporaryToken<String>, _>(crate::Error::Generic {
                    store: "test",
                    source: "credential endpoint unavailable".into(),
                })
            })
            .await
            .unwrap_err();
        assert!(err.to_string().contains("credential endpoint unavailable"));
        let token = cache
            .get_or_insert_with(|| async { Ok::<_, crate::Error>(create_token(None)) })
            .await
            .unwrap();
        assert_eq!(token, "test_token");
    }
}
