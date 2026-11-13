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

#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
fn get_or_start_runtime(
    runtime: &parking_lot::Mutex<Option<tokio::runtime::Handle>>,
    start: impl FnOnce() -> std::io::Result<tokio::runtime::Handle>,
) -> std::io::Result<tokio::runtime::Handle> {
    let mut runtime = runtime.lock();
    if let Some(handle) = runtime.as_ref() {
        return Ok(handle.clone());
    }
    let handle = start()?;
    *runtime = Some(handle.clone());
    Ok(handle)
}

#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
fn credential_runtime() -> crate::Result<tokio::runtime::Handle> {
    static RUNTIME: parking_lot::Mutex<Option<tokio::runtime::Handle>> =
        parking_lot::Mutex::new(None);
    get_or_start_runtime(&RUNTIME, || {
        let (send, receive) = std::sync::mpsc::sync_channel(1);
        std::thread::Builder::new()
            .name("object-store-credentials".into())
            .spawn(move || {
                match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(runtime) => {
                        if send.send(Ok(runtime.handle().clone())).is_ok() {
                            runtime.block_on(std::future::pending::<()>());
                        }
                    }
                    Err(error) => {
                        let _ = send.send(Err(error));
                    }
                }
            })?;
        receive.recv().map_err(std::io::Error::other)?
    })
    .map_err(|source| crate::Error::Generic {
        store: "TokenCache",
        source: Box::new(source),
    })
}

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
    refresh_timeout: Duration,
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
            refresh_timeout: TOKEN_REFRESH_TIMEOUT,
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
        let refresh_timeout = self.refresh_timeout;
        let refresh = async move {
            let cached = tokio::time::timeout(refresh_timeout, fetch)
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
            credential_runtime()?
                .spawn(refresh)
                .await
                .map_err(crate::Error::from)?
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

    const TEST_WAIT_TIMEOUT: Duration = Duration::from_secs(5);
    const TEST_REFRESH_TIMEOUT: Duration = Duration::from_millis(20);
    const TEST_TIMER_DELAY: Duration = Duration::from_millis(1);

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
            Ok::<_, crate::Error>(create_token(Some(Duration::ZERO)))
        }

        // Should fetch initial token
        let _ = cache.get_or_insert_with(get_token).await.unwrap();
        assert_eq!(COUNTER.load(Ordering::SeqCst), 1);

        // Token is expired, so should fetch again
        let _ = cache.get_or_insert_with(get_token).await.unwrap();
        assert_eq!(COUNTER.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn test_min_ttl_causes_refresh() {
        const TOKEN_LIFETIME: Duration = Duration::from_secs(3600);
        let cache = TokenCache {
            min_ttl: TOKEN_LIFETIME * 2,
            fetch_backoff: TOKEN_LIFETIME,
            ..Default::default()
        };
        static COUNTER: AtomicU32 = AtomicU32::new(0);

        async fn get_token() -> crate::Result<TemporaryToken<String>> {
            COUNTER.fetch_add(1, Ordering::SeqCst);
            Ok(create_token(Some(TOKEN_LIFETIME)))
        }

        cache.get_or_insert_with(get_token).await.unwrap();
        assert_eq!(COUNTER.load(Ordering::SeqCst), 1);

        cache.get_or_insert_with(get_token).await.unwrap();
        assert_eq!(COUNTER.load(Ordering::SeqCst), 1);

        cache.cache.write().await.as_mut().unwrap().fetched_at =
            Instant::now() - cache.fetch_backoff;
        cache.get_or_insert_with(get_token).await.unwrap();
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
        tokio::time::timeout(TEST_WAIT_TIMEOUT, started_wait)
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
            TEST_WAIT_TIMEOUT,
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
        let cache = TokenCache::<String> {
            refresh_timeout: TEST_REFRESH_TIMEOUT,
            ..Default::default()
        };
        let (started, started_wait) = tokio::sync::oneshot::channel();
        let (mut cancelled_wait, cancelled) = tokio::sync::oneshot::channel::<()>();
        let mut request = Box::pin(cache.get_or_insert_with(|| async move {
            started.send(()).unwrap();
            cancelled.await.unwrap();
            Ok::<_, crate::Error>(create_token(None))
        }));
        assert!(request.as_mut().now_or_never().is_none());
        tokio::time::timeout(TEST_WAIT_TIMEOUT, started_wait)
            .await
            .expect("credential fetch did not start")
            .unwrap();
        let mut request = if drop_request {
            drop(request);
            None
        } else {
            Some(request)
        };
        tokio::time::timeout(TEST_WAIT_TIMEOUT, cancelled_wait.closed())
            .await
            .expect("timed-out fetch was not dropped");
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

    #[tokio::test]
    async fn test_refresh_times_out_without_polling_request() {
        refresh_timeout_releases_cache(false).await;
    }

    #[tokio::test]
    async fn test_refresh_times_out_after_request_is_dropped() {
        refresh_timeout_releases_cache(true).await;
    }

    #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
    #[test]
    fn test_runtime_startup_failure_can_retry() {
        let runtime = parking_lot::Mutex::new(None);
        let error = super::get_or_start_runtime(&runtime, || {
            Err(std::io::Error::new(
                std::io::ErrorKind::WouldBlock,
                "temporary thread startup failure",
            ))
        })
        .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::WouldBlock);
        assert!(runtime.lock().is_none());

        let owner = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        super::get_or_start_runtime(&runtime, || Ok(owner.handle().clone())).unwrap();
        let handle = super::get_or_start_runtime(&runtime, || {
            panic!("successful runtime initialization must be reused")
        })
        .unwrap();
        assert_eq!(
            owner.block_on(handle.spawn(async { "ready" })).unwrap(),
            "ready"
        );
    }

    #[test]
    fn test_refresh_without_callers_tokio_runtime() {
        let cache = TokenCache::<String>::default();
        let caller = std::thread::current().id();
        let token = futures_executor::block_on(cache.get_or_insert_with(|| async move {
            assert_ne!(std::thread::current().id(), caller);
            tokio::time::sleep(TEST_TIMER_DELAY).await;
            Ok::<_, crate::Error>(create_token(None))
        }))
        .unwrap();
        assert_eq!(token, "test_token");
    }

    #[test]
    fn test_refresh_completes_when_callers_runtime_stops() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let cache = TokenCache::<String>::default();
        let (started, started_wait) = tokio::sync::oneshot::channel();
        let (release, release_wait) = tokio::sync::oneshot::channel();
        let (completed, completed_wait) = std::sync::mpsc::channel();
        let mut request = Box::pin(cache.get_or_insert_with(|| async move {
            started.send(()).unwrap();
            release_wait.await.unwrap();
            tokio::time::sleep(TEST_TIMER_DELAY).await;
            completed.send(()).unwrap();
            Ok::<_, crate::Error>(create_token(None))
        }));
        runtime.block_on(async {
            assert!(request.as_mut().now_or_never().is_none());
            tokio::time::timeout(TEST_WAIT_TIMEOUT, started_wait)
                .await
                .expect("credential fetch did not start")
                .unwrap();
        });
        release.send(()).unwrap();
        completed_wait
            .recv_timeout(TEST_WAIT_TIMEOUT)
            .expect("credential refresh depends on the caller's stopped runtime");
        assert_eq!(futures_executor::block_on(request).unwrap(), "test_token");
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
