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

use std::collections::HashMap;
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::{Duration, Instant};

use rand::prelude::SliceRandom;
use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use tokio::sync::Notify;
use tokio::task::JoinSet;
use tracing::{Instrument, field, info_span, warn};

type DynErr = Box<dyn std::error::Error + Send + Sync>;

const SLOW_DNS_RESOLVE_LOG_THRESHOLD_MS: u128 = 500;
const DNS_CACHE_TTL: Duration = Duration::from_secs(60);

static DNS_CACHE: LazyLock<Mutex<HashMap<String, DnsCacheEntry>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

enum DnsCacheEntry {
    Ready {
        addrs: Vec<SocketAddr>,
        expires_at: Instant,
    },
    Resolving {
        notify: Arc<Notify>,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DnsCacheStatus {
    Hit,
    Wait,
    Lookup,
}

impl DnsCacheStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Hit => "hit",
            Self::Wait => "wait",
            Self::Lookup => "lookup",
        }
    }
}

#[derive(Debug)]
pub(crate) struct ShuffleResolver;

impl Resolve for ShuffleResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let host = name.as_str().to_string();
        let host_for_span = host.clone();
        let span = info_span!(
            "object_store dns resolve",
            host = %host_for_span,
            cache_status = field::Empty,
        );
        Box::pin(
            async move {
                let start = Instant::now();
                let result = resolve_with_cache(host.clone()).await;
                let elapsed = start.elapsed();
                let status = result
                    .as_ref()
                    .map(|(_, status)| *status)
                    .unwrap_or(DnsCacheStatus::Lookup);
                tracing::Span::current().record("cache_status", status.as_str());
                if status == DnsCacheStatus::Lookup
                    && elapsed.as_millis() >= SLOW_DNS_RESOLVE_LOG_THRESHOLD_MS
                {
                    warn!(
                        host = %host,
                        elapsed_ms = elapsed.as_millis(),
                        error = result.as_ref().err().map(|x| x.to_string()),
                        cache_status = status.as_str(),
                        "Slow object_store DNS resolve"
                    );
                }
                result.map(|(mut addrs, _)| {
                    addrs.shuffle(&mut rand::rng());
                    Box::new(addrs.into_iter()) as Addrs
                })
            }
            .instrument(span),
        )
    }
}

async fn resolve_with_cache(host: String) -> Result<(Vec<SocketAddr>, DnsCacheStatus), DynErr> {
    let mut waited = false;
    loop {
        let notify = {
            let now = Instant::now();
            let mut cache = DNS_CACHE.lock().unwrap();

            match cache.get(&host) {
                Some(DnsCacheEntry::Ready { addrs, expires_at }) if *expires_at > now => {
                    let status = if waited {
                        DnsCacheStatus::Wait
                    } else {
                        DnsCacheStatus::Hit
                    };
                    return Ok((addrs.clone(), status));
                }
                Some(DnsCacheEntry::Resolving { notify }) => Some(Arc::clone(notify)),
                _ => {
                    let notify = Arc::new(Notify::new());
                    cache.insert(
                        host.clone(),
                        DnsCacheEntry::Resolving {
                            notify: Arc::clone(&notify),
                        },
                    );
                    None
                }
            }
        };

        if let Some(notify) = notify {
            waited = true;
            notify.notified().await;
            continue;
        }

        return resolve_and_cache(host).await;
    }
}

async fn resolve_and_cache(host: String) -> Result<(Vec<SocketAddr>, DnsCacheStatus), DynErr> {
    let mut guard = DnsResolveGuard::new(host.clone());
    let result = resolve_uncached(host.clone()).await;
    let notify = guard.notify.clone();

    let mut cache = DNS_CACHE.lock().unwrap();
    match &result {
        Ok(addrs) if !addrs.is_empty() => {
            cache.insert(
                host,
                DnsCacheEntry::Ready {
                    addrs: addrs.clone(),
                    expires_at: Instant::now() + DNS_CACHE_TTL,
                },
            );
        }
        Ok(_) | Err(_) => {
            cache.remove(&host);
        }
    }
    guard.disarm();
    drop(cache);
    if let Some(notify) = notify {
        notify.notify_waiters();
    }

    result.map(|addrs| (addrs, DnsCacheStatus::Lookup))
}

async fn resolve_uncached(host: String) -> Result<Vec<SocketAddr>, DynErr> {
    // use `JoinSet` to propagate cancelation to tasks that haven't started running yet.
    let mut tasks = JoinSet::new();
    tasks.spawn_blocking(move || -> std::io::Result<Vec<SocketAddr>> {
        (host.as_str(), 0).to_socket_addrs().map(Iterator::collect)
    });

    match tasks.join_next().await.expect("spawned on task") {
        Ok(Ok(addrs)) => Ok(addrs),
        Ok(Err(err)) => Err(Box::new(err) as DynErr),
        Err(err) => Err(Box::new(err) as DynErr),
    }
}

struct DnsResolveGuard {
    host: String,
    notify: Option<Arc<Notify>>,
}

impl DnsResolveGuard {
    fn new(host: String) -> Self {
        let notify = match DNS_CACHE.lock().unwrap().get(&host) {
            Some(DnsCacheEntry::Resolving { notify }) => Some(Arc::clone(notify)),
            _ => None,
        };
        Self { host, notify }
    }

    fn disarm(&mut self) {
        self.notify = None;
    }
}

impl Drop for DnsResolveGuard {
    fn drop(&mut self) {
        let Some(notify) = &self.notify else {
            return;
        };

        let mut cache = DNS_CACHE.lock().unwrap();
        if matches!(
            cache.get(&self.host),
            Some(DnsCacheEntry::Resolving { notify: in_flight }) if Arc::ptr_eq(in_flight, notify)
        ) {
            cache.remove(&self.host);
        }
        notify.notify_waiters();
    }
}
