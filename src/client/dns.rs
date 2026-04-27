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
use std::time::Instant;

use rand::prelude::SliceRandom;
use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use tokio::task::JoinSet;
use tracing::{Instrument, info_span, warn};

type DynErr = Box<dyn std::error::Error + Send + Sync>;

const SLOW_DNS_RESOLVE_LOG_THRESHOLD_MS: u128 = 500;

#[derive(Debug)]
pub(crate) struct ShuffleResolver;

impl Resolve for ShuffleResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let host = name.as_str().to_string();
        let host_for_span = host.clone();
        let span = info_span!("object_store dns resolve", host = %host_for_span);
        Box::pin(
            async move {
                let start = Instant::now();
                // use `JoinSet` to propagate cancelation to tasks that haven't started running yet.
                let mut tasks = JoinSet::new();
                tasks.spawn_blocking(move || -> std::io::Result<Addrs> {
                    let it = (name.as_str(), 0).to_socket_addrs()?;
                    let mut addrs = it.collect::<Vec<_>>();

                    addrs.shuffle(&mut rand::rng());

                    Ok(Box::new(addrs.into_iter()) as Addrs)
                });

                let result = match tasks.join_next().await.expect("spawned on task") {
                    Ok(Ok(addrs)) => Ok(addrs),
                    Ok(Err(err)) => Err(Box::new(err) as DynErr),
                    Err(err) => Err(Box::new(err) as DynErr),
                };
                let elapsed = start.elapsed();
                if elapsed.as_millis() >= SLOW_DNS_RESOLVE_LOG_THRESHOLD_MS {
                    warn!(
                        host = %host,
                        elapsed_ms = elapsed.as_millis(),
                        error = result.as_ref().err().map(|x| x.to_string()),
                        "Slow object_store DNS resolve"
                    );
                }
                result
            }
            .instrument(span),
        )
    }
}
