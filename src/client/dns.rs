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

use std::net::ToSocketAddrs;
use std::sync::Arc;

#[cfg(feature = "hickory-dns")]
use hickory_resolver::{config::LookupIpStrategy, TokioResolver};
use rand::prelude::SliceRandom;
use reqwest::dns::{Addrs, Name, Resolve, Resolving};
#[cfg(feature = "hickory-dns")]
use tokio::sync::OnceCell;
use tokio::task::JoinSet;

type DynErr = Box<dyn std::error::Error + Send + Sync>;

#[derive(Debug, Default)]
pub(crate) struct ShuffleResolver;

impl Resolve for ShuffleResolver {
    fn resolve(&self, name: Name) -> Resolving {
        resolve_socket_addrs(name)
    }
}

#[cfg(feature = "hickory-dns")]
#[derive(Debug, Default)]
pub(crate) struct HickoryShuffleResolver {
    hickory: Arc<OnceCell<TokioResolver>>,
}

#[cfg(feature = "hickory-dns")]
impl Resolve for HickoryShuffleResolver {
    fn resolve(&self, name: Name) -> Resolving {
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
