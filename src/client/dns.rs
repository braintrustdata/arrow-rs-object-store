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
use std::sync::Arc;

use hickory_resolver::{TokioResolver, config::LookupIpStrategy};
use rand::prelude::SliceRandom;
use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use tokio::sync::OnceCell;

#[derive(Debug, Default)]
pub(crate) struct ShuffleResolver {
    resolver: Arc<OnceCell<TokioResolver>>,
}

impl Resolve for ShuffleResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let resolver = Arc::clone(&self.resolver);
        Box::pin(async move {
            let resolver = resolver
                .get_or_try_init(|| async {
                    let mut builder = TokioResolver::builder_tokio()?;
                    builder.options_mut().ip_strategy = LookupIpStrategy::Ipv4AndIpv6;
                    Ok::<_, hickory_resolver::ResolveError>(builder.build())
                })
                .await?;
            let mut addrs = resolver
                .lookup_ip(name.as_str())
                .await?
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
    use hickory_resolver::config::{NameServerConfig, ResolveHosts, ResolverConfig};
    use hickory_resolver::name_server::TokioConnectionProvider;
    use hickory_resolver::proto::op::{Message, MessageType};
    use hickory_resolver::proto::rr::{RData, Record, rdata::A};
    use hickory_resolver::proto::xfer::Protocol;
    use tokio::net::UdpSocket;
    use tokio::time::{Duration, timeout};

    #[tokio::test]
    async fn caches_dns_answers_and_reshuffles_cache_hits() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut config = ResolverConfig::new();
        config.add_name_server(NameServerConfig::new(
            socket.local_addr().unwrap(),
            Protocol::Udp,
        ));
        let mut builder =
            TokioResolver::builder_with_config(config, TokioConnectionProvider::default());
        builder.options_mut().ip_strategy = LookupIpStrategy::Ipv4Only;
        builder.options_mut().use_hosts_file = ResolveHosts::Never;
        let resolver = ShuffleResolver {
            resolver: Arc::new(OnceCell::new_with(Some(builder.build()))),
        };
        let server = tokio::spawn(async move {
            let mut buf = [0; 512];
            let (len, peer) = socket.recv_from(&mut buf).await.unwrap();
            let request = Message::from_vec(&buf[..len]).unwrap();
            let mut response = Message::new();
            response
                .set_id(request.id())
                .set_message_type(MessageType::Response)
                .set_recursion_desired(true)
                .set_recursion_available(true)
                .add_queries(request.queries().iter().cloned());
            for last_octet in 1..=4 {
                response.add_answer(Record::from_rdata(
                    request.queries()[0].name().clone(),
                    60,
                    RData::A(A::new(192, 0, 2, last_octet)),
                ));
            }
            socket
                .send_to(&response.to_vec().unwrap(), peer)
                .await
                .unwrap();
        });

        let first = resolver
            .resolve("s3.example.".parse().unwrap())
            .await
            .unwrap()
            .collect::<Vec<_>>();
        server.await.unwrap();
        assert_eq!(first.len(), 4);
        let mut expected = first.clone();
        expected.sort_unstable();
        let mut reshuffled = false;
        for _ in 0..32 {
            let mut addrs = timeout(
                Duration::from_secs(1),
                resolver.resolve("s3.example.".parse().unwrap()),
            )
            .await
            .unwrap()
            .unwrap()
            .collect::<Vec<_>>();
            reshuffled |= addrs != first;
            addrs.sort_unstable();
            assert_eq!(addrs, expected);
        }
        assert!(reshuffled);
    }
}
