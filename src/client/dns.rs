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

#[cfg(not(feature = "hickory-dns"))]
use std::net::ToSocketAddrs;
#[cfg(feature = "hickory-dns")]
use std::sync::Arc;

#[cfg(feature = "hickory-dns")]
use hickory_resolver::{config::LookupIpStrategy, TokioResolver};
use rand::prelude::SliceRandom;
use reqwest::dns::{Addrs, Name, Resolve, Resolving};
#[cfg(feature = "hickory-dns")]
use tokio::sync::OnceCell;
#[cfg(not(feature = "hickory-dns"))]
use tokio::task::JoinSet;

type DynErr = Box<dyn std::error::Error + Send + Sync>;

#[derive(Debug, Default)]
pub(crate) struct ShuffleResolver {
    #[cfg(feature = "hickory-dns")]
    hickory: Arc<OnceCell<TokioResolver>>,
}

impl Resolve for ShuffleResolver {
    fn resolve(&self, name: Name) -> Resolving {
        #[cfg(feature = "hickory-dns")]
        {
            return self.resolve_hickory(name);
        }

        #[cfg(not(feature = "hickory-dns"))]
        {
            resolve_socket_addrs(name)
        }
    }
}

#[cfg(feature = "hickory-dns")]
impl ShuffleResolver {
    fn resolve_hickory(&self, name: Name) -> Resolving {
        let resolver = Arc::clone(&self.hickory);

        Box::pin(async move {
            let resolver = resolver
                .get_or_try_init(|| async {
                    let mut builder = TokioResolver::builder_tokio()
                        .map_err(|err| -> DynErr { Box::new(err) })?;
                    builder.options_mut().ip_strategy = LookupIpStrategy::Ipv4AndIpv6;
                    Ok::<TokioResolver, DynErr>(builder.build())
                })
                .await?;

            let mut addrs = resolver
                .lookup_ip(name.as_str())
                .await?
                .into_iter()
                .map(|ip_addr| std::net::SocketAddr::new(ip_addr, 0))
                .collect::<Vec<_>>();

            addrs.shuffle(&mut rand::rng());

            Ok(Box::new(addrs.into_iter()) as Addrs)
        })
    }
}

#[cfg(not(feature = "hickory-dns"))]
fn resolve_socket_addrs(name: Name) -> Resolving {
    Box::pin(async move {
        // use `JoinSet` to propagate cancelation
        let mut tasks = JoinSet::new();
        tasks.spawn_blocking(move || {
            let it = (name.as_str(), 0).to_socket_addrs()?;
            let mut addrs = it.collect::<Vec<_>>();

            addrs.shuffle(&mut rand::rng());

            Ok(Box::new(addrs.into_iter()) as Addrs)
        });

        tasks
            .join_next()
            .await
            .expect("spawned on task")
            .map_err(|err| Box::new(err) as DynErr)?
    })
}
