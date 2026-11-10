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
