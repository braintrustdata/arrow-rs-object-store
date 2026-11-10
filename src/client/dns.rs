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

use std::net::SocketAddr;
use std::sync::{Arc, OnceLock};

use hickory_resolver::TokioResolver;
use hickory_resolver::config::LookupIpStrategy;
use rand::prelude::SliceRandom;
use reqwest::dns::{Addrs, Name, Resolve, Resolving};

type DynErr = Box<dyn std::error::Error + Send + Sync>;

#[derive(Debug, Default)]
pub(crate) struct ShuffleResolver {
    // Built on first lookup. `builder_tokio` must run inside a Tokio runtime,
    // and reqwest may construct this resolver before one is installed.
    resolver: Arc<OnceLock<TokioResolver>>,
}

impl ShuffleResolver {
    fn resolver(slot: &OnceLock<TokioResolver>) -> Result<TokioResolver, DynErr> {
        if let Some(resolver) = slot.get() {
            return Ok(resolver.clone());
        }
        let mut builder = TokioResolver::builder_tokio()?;
        builder.options_mut().ip_strategy = LookupIpStrategy::Ipv4AndIpv6;
        let _ = slot.set(builder.build());
        slot.get()
            .cloned()
            .ok_or_else(|| "Hickory resolver was not installed".into())
    }

    #[cfg(test)]
    fn from_resolver(resolver: TokioResolver) -> Self {
        let slot = OnceLock::new();
        slot.set(resolver).expect("empty lock");
        Self {
            resolver: Arc::new(slot),
        }
    }
}

impl Resolve for ShuffleResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let slot = Arc::clone(&self.resolver);
        Box::pin(async move {
            let resolver = Self::resolver(&slot)?;
            let lookup = resolver.lookup_ip(name.as_str()).await?;
            let mut addrs = lookup
                .iter()
                .map(|ip| SocketAddr::new(ip, 0))
                .collect::<Vec<_>>();
            addrs.shuffle(&mut rand::rng());
            Ok(Box::new(addrs.into_iter()) as Addrs)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::HashSet;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr as StdSocketAddr, UdpSocket};
    use std::str::FromStr;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::thread;
    use std::time::Duration;

    use hickory_resolver::config::{NameServerConfig, ResolverConfig};
    use hickory_resolver::name_server::TokioConnectionProvider;
    use hickory_resolver::proto::xfer::Protocol;

    async fn collect(resolver: &ShuffleResolver, host: &str) -> Vec<SocketAddr> {
        let name = Name::from_str(host).unwrap();
        resolver.resolve(name).await.unwrap().collect::<Vec<_>>()
    }

    /// Answers A with four addresses and AAAA with one, all with a long TTL.
    fn reply(query: &[u8]) -> Option<Vec<u8>> {
        if query.len() < 12 {
            return None;
        }
        let mut end = 12;
        while end < query.len() {
            let len = query[end] as usize;
            if len == 0 {
                end += 1;
                break;
            }
            if len > 63 || end + 1 + len > query.len() {
                return None;
            }
            end += 1 + len;
        }
        if end + 4 > query.len() {
            return None;
        }
        let qtype = u16::from_be_bytes([query[end], query[end + 1]]);
        let mut out = query[..end + 4].to_vec();
        out[2] = 0x84 | (query[2] & 0x01);
        out[3] = 0x80;
        out[4] = 0;
        out[5] = 1;
        out[8] = 0;
        out[9] = 0;
        out[10] = 0;
        out[11] = 0;

        let records: &[&[u8]] = match qtype {
            1 => &[
                &[10, 0, 0, 1],
                &[10, 0, 0, 2],
                &[10, 0, 0, 3],
                &[10, 0, 0, 4],
            ],
            28 => &[&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]],
            _ => &[],
        };
        out[6] = 0;
        out[7] = records.len() as u8;
        for rdata in records {
            out.extend_from_slice(&[0xc0, 0x0c]);
            out.extend_from_slice(&qtype.to_be_bytes());
            out.extend_from_slice(&1u16.to_be_bytes());
            out.extend_from_slice(&300u32.to_be_bytes());
            out.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
            out.extend_from_slice(rdata);
        }
        Some(out)
    }

    fn serve(stop: &Arc<AtomicBool>, queries: &Arc<AtomicUsize>) -> StdSocketAddr {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        socket
            .set_read_timeout(Some(Duration::from_millis(50)))
            .unwrap();
        let addr = socket.local_addr().unwrap();
        let stop = Arc::clone(stop);
        let queries = Arc::clone(queries);
        thread::spawn(move || {
            let mut buf = [0u8; 512];
            while !stop.load(Ordering::Relaxed) {
                match socket.recv_from(&mut buf) {
                    Ok((n, peer)) => {
                        queries.fetch_add(1, Ordering::SeqCst);
                        if let Some(response) = reply(&buf[..n]) {
                            let _ = socket.send_to(&response, peer);
                        }
                    }
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {}
                    Err(err) if err.kind() == std::io::ErrorKind::TimedOut => {}
                    Err(_) => break,
                }
            }
        });
        addr
    }

    #[tokio::test]
    async fn caches_lookups_and_shuffles_addresses() {
        let stop = Arc::new(AtomicBool::new(false));
        let queries = Arc::new(AtomicUsize::new(0));
        let addr = serve(&stop, &queries);

        let mut builder = TokioResolver::builder_with_config(
            ResolverConfig::from_parts(
                None,
                Vec::new(),
                vec![NameServerConfig::new(addr, Protocol::Udp)],
            ),
            TokioConnectionProvider::default(),
        );
        let options = builder.options_mut();
        options.ip_strategy = LookupIpStrategy::Ipv4AndIpv6;
        options.attempts = 1;
        options.ndots = 1;
        options.try_tcp_on_error = false;
        options.timeout = Duration::from_secs(2);
        let resolver = ShuffleResolver::from_resolver(builder.build());

        let expected = HashSet::from([
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 4)),
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
        ]);

        let first = collect(&resolver, "cache.example.com").await;
        assert!(first.iter().all(|addr| addr.port() == 0));
        assert_eq!(
            first.iter().map(|addr| addr.ip()).collect::<HashSet<_>>(),
            expected
        );
        let queries_after_first = queries.load(Ordering::SeqCst);
        assert!(
            queries_after_first > 0,
            "resolver did not query the stub server"
        );

        let mut first_addrs = HashSet::from([first[0].ip()]);
        for _ in 0..19 {
            let addrs = collect(&resolver, "cache.example.com").await;
            assert_eq!(
                addrs.iter().map(|addr| addr.ip()).collect::<HashSet<_>>(),
                expected
            );
            first_addrs.insert(addrs[0].ip());
        }
        assert_eq!(
            queries.load(Ordering::SeqCst),
            queries_after_first,
            "a cached name was sent to DNS again"
        );
        assert!(
            first_addrs.len() > 1,
            "every lookup returned addresses in the same order"
        );

        stop.store(true, Ordering::Relaxed);
    }

    #[tokio::test]
    async fn system_resolver_resolves_localhost() {
        let resolver = ShuffleResolver::default();
        let addrs = collect(&resolver, "localhost").await;
        assert!(
            addrs.iter().any(|addr| {
                addr.ip() == IpAddr::V4(Ipv4Addr::LOCALHOST)
                    || addr.ip() == IpAddr::V6(Ipv6Addr::LOCALHOST)
            }),
            "localhost resolved to {addrs:?}"
        );
    }
}
