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

use crate::client::{
    HttpError, HttpErrorKind, HttpRequest, HttpResponse, HttpResponseBody, HttpService,
};
use async_trait::async_trait;
use bytes::Bytes;
use http::Response;
use http_body_util::BodyExt;
use hyper::body::{Body, Frame};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Instant;
use thiserror::Error;
use tokio::runtime::Handle;
use tokio::task::JoinHandle;
use tracing::warn;

const SLOW_FOOTER_SPAWN_LOG_THRESHOLD_MS: u128 = 500;

#[derive(Clone, Debug)]
struct FooterSpawnFields {
    method: String,
    host: String,
    path: String,
}

fn footer_spawn_fields(req: &HttpRequest) -> Option<FooterSpawnFields> {
    let path = req.uri().path();
    let is_footer =
        path.ends_with(".footer") || path.contains("%2Efooter") || path.contains("%2efooter");

    is_footer.then(|| FooterSpawnFields {
        method: req.method().to_string(),
        host: req.uri().host().unwrap_or("").to_string(),
        path: path.to_string(),
    })
}

/// Spawn error
#[derive(Debug, Error)]
#[error("SpawnError")]
struct SpawnError {}

impl From<SpawnError> for HttpError {
    fn from(value: SpawnError) -> Self {
        Self::new(HttpErrorKind::Interrupted, value)
    }
}

/// Wraps a provided [`HttpService`] and runs it on a separate tokio runtime
///
/// See example on [`SpawnedReqwestConnector`]
///
/// [`SpawnedReqwestConnector`]: crate::client::http::SpawnedReqwestConnector
#[derive(Debug)]
pub struct SpawnService<T: HttpService + Clone> {
    inner: T,
    runtime: Handle,
}

impl<T: HttpService + Clone> SpawnService<T> {
    /// Creates a new [`SpawnService`] from the provided
    pub fn new(inner: T, runtime: Handle) -> Self {
        Self { inner, runtime }
    }
}

#[async_trait]
impl<T: HttpService + Clone> HttpService for SpawnService<T> {
    async fn call(&self, req: HttpRequest) -> Result<HttpResponse, HttpError> {
        let inner = self.inner.clone();
        let footer_fields = footer_spawn_fields(&req);
        let call_start = Instant::now();
        let (send, recv) = tokio::sync::oneshot::channel();

        // We use an unbounded channel to prevent backpressure across the runtime boundary
        // which could in turn starve the underlying IO operations
        let (sender, receiver) = tokio::sync::mpsc::unbounded_channel();

        let worker_footer_fields = footer_fields.clone();
        let handle = SpawnHandle(self.runtime.spawn(async move {
            if let Some(fields) = &worker_footer_fields {
                let elapsed = call_start.elapsed();
                if elapsed.as_millis() >= SLOW_FOOTER_SPAWN_LOG_THRESHOLD_MS {
                    warn!(
                        method = %fields.method,
                        host = %fields.host,
                        path = %fields.path,
                        elapsed_ms = elapsed.as_millis(),
                        "Slow object_store footer spawn handoff"
                    );
                }
            }

            let inner_start = Instant::now();
            let r = match HttpService::call(&inner, req).await {
                Ok(resp) => {
                    if let Some(fields) = &worker_footer_fields {
                        let elapsed = inner_start.elapsed();
                        if elapsed.as_millis() >= SLOW_FOOTER_SPAWN_LOG_THRESHOLD_MS {
                            warn!(
                                method = %fields.method,
                                host = %fields.host,
                                path = %fields.path,
                                elapsed_ms = elapsed.as_millis(),
                                "Slow object_store footer spawned inner HTTP call"
                            );
                        }
                    }
                    resp
                }
                Err(e) => {
                    if let Some(fields) = &worker_footer_fields {
                        let elapsed = inner_start.elapsed();
                        if elapsed.as_millis() >= SLOW_FOOTER_SPAWN_LOG_THRESHOLD_MS {
                            warn!(
                                method = %fields.method,
                                host = %fields.host,
                                path = %fields.path,
                                elapsed_ms = elapsed.as_millis(),
                                error = %e,
                                "Slow object_store footer spawned inner HTTP call"
                            );
                        }
                    }
                    let _ = send.send(Err(e));
                    return;
                }
            };

            let (parts, mut body) = r.into_parts();
            let response_parts_ready_at = Instant::now();
            if send.send(Ok((parts, response_parts_ready_at))).is_err() {
                return;
            }

            let body_start = Instant::now();
            let mut frame_index = 0u64;
            let mut bytes_sent = 0usize;
            while let Some(x) = body.frame().await {
                if let Some(fields) = &worker_footer_fields {
                    let elapsed = body_start.elapsed();
                    let frame_bytes = x
                        .as_ref()
                        .ok()
                        .and_then(|frame| frame.data_ref())
                        .map(|data| data.len());
                    if let Some(frame_bytes) = frame_bytes {
                        bytes_sent += frame_bytes;
                    }
                    if elapsed.as_millis() >= SLOW_FOOTER_SPAWN_LOG_THRESHOLD_MS {
                        warn!(
                            method = %fields.method,
                            host = %fields.host,
                            path = %fields.path,
                            elapsed_ms = elapsed.as_millis(),
                            frame_index,
                            frame_bytes,
                            bytes_sent,
                            error = x.as_ref().err().map(|error| error.to_string()).as_deref(),
                            "Slow object_store footer spawned body frame"
                        );
                    }
                }
                if sender.send(x).is_err() {
                    return;
                }
                frame_index += 1;
            }

            if let Some(fields) = &worker_footer_fields {
                let elapsed = body_start.elapsed();
                if elapsed.as_millis() >= SLOW_FOOTER_SPAWN_LOG_THRESHOLD_MS {
                    warn!(
                        method = %fields.method,
                        host = %fields.host,
                        path = %fields.path,
                        elapsed_ms = elapsed.as_millis(),
                        frame_count = frame_index,
                        bytes_sent,
                        "Slow object_store footer spawned body stream"
                    );
                }
            }
        }));

        let (parts, response_parts_ready_at) = recv.await.map_err(|_| SpawnError {})??;
        if let Some(fields) = &footer_fields {
            let elapsed = call_start.elapsed();
            if elapsed.as_millis() >= SLOW_FOOTER_SPAWN_LOG_THRESHOLD_MS {
                let worker_elapsed = response_parts_ready_at.duration_since(call_start);
                let response_parts_recv_lag = response_parts_ready_at.elapsed();
                warn!(
                    method = %fields.method,
                    host = %fields.host,
                    path = %fields.path,
                    elapsed_ms = elapsed.as_millis(),
                    worker_elapsed_ms = worker_elapsed.as_millis(),
                    response_parts_recv_lag_ms = response_parts_recv_lag.as_millis(),
                    "Slow object_store footer spawned response parts"
                );
            }
        }

        Ok(Response::from_parts(
            parts,
            HttpResponseBody::new(SpawnBody {
                stream: receiver,
                _worker: handle,
                footer_fields,
                pending_since: None,
                frame_index: 0,
            }),
        ))
    }
}

/// A wrapper around a [`JoinHandle`] that aborts on drop
struct SpawnHandle(JoinHandle<()>);
impl Drop for SpawnHandle {
    fn drop(&mut self) {
        self.0.abort();
    }
}

type StreamItem = Result<Frame<Bytes>, HttpError>;

struct SpawnBody {
    stream: tokio::sync::mpsc::UnboundedReceiver<StreamItem>,
    _worker: SpawnHandle,
    footer_fields: Option<FooterSpawnFields>,
    pending_since: Option<Instant>,
    frame_index: u64,
}

impl Body for SpawnBody {
    type Data = Bytes;
    type Error = HttpError;

    fn poll_frame(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<StreamItem>> {
        match self.stream.poll_recv(cx) {
            Poll::Pending => {
                if self.footer_fields.is_some() && self.pending_since.is_none() {
                    self.pending_since = Some(Instant::now());
                }
                Poll::Pending
            }
            Poll::Ready(item) => {
                let footer_fields = self.footer_fields.clone();
                let pending_since = self.pending_since.take();
                if let (Some(fields), Some(pending_since)) = (footer_fields, pending_since) {
                    let elapsed = pending_since.elapsed();
                    if elapsed.as_millis() >= SLOW_FOOTER_SPAWN_LOG_THRESHOLD_MS {
                        warn!(
                            method = %fields.method,
                            host = %fields.host,
                            path = %fields.path,
                            elapsed_ms = elapsed.as_millis(),
                            frame_index = self.frame_index,
                            "Slow object_store footer spawned body recv"
                        );
                    }
                }
                self.frame_index += 1;
                Poll::Ready(item)
            }
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::RetryConfig;
    use crate::client::HttpClient;
    use crate::client::mock_server::MockServer;
    use crate::client::retry::RetryExt;

    async fn test_client(client: HttpClient) {
        let (send, recv) = tokio::sync::oneshot::channel();

        let mock = MockServer::new().await;
        mock.push(Response::new("BANANAS".to_string()));

        let url = mock.url().to_string();
        let thread = std::thread::spawn(|| {
            futures_executor::block_on(async move {
                let retry = RetryConfig::default();
                let ret = client.get(url).send_retry(&retry).await.unwrap();
                let payload = ret.into_body().bytes().await.unwrap();
                assert_eq!(payload.as_ref(), b"BANANAS");
                let _ = send.send(());
            })
        });
        recv.await.unwrap();
        thread.join().unwrap();
    }

    #[tokio::test]
    async fn test_spawn() {
        let client = HttpClient::new(SpawnService::new(reqwest::Client::new(), Handle::current()));
        test_client(client).await;
    }

    #[tokio::test]
    #[should_panic]
    async fn test_no_spawn() {
        let client = HttpClient::new(reqwest::Client::new());
        test_client(client).await;
    }
}
