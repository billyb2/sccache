// Copyright 2016 Mozilla Foundation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Client-side QUIC transport to the billdfaster gateway.
//!
//! Selected once per dist client (`[dist] quic = true`); when enabled every
//! asynchronous scheduler and worker RPC travels over this transport and the
//! pinned-certificate HTTP transport is left untouched but unused. The client
//! keeps exactly one QUIC endpoint, rustls session store and (while idle
//! permits) one connection on the daemon's Tokio runtime, so sequential
//! requests reuse the connection and TLS sessions are resumed across
//! reconnects. Certificate updates never reset this state.
//!
//! Wire v1 (mirrored byte for byte by the gateway):
//! - ALPN `billdfaster/1`, one bidirectional stream per request.
//! - Request: 4-byte big-endian JSON header length (1..=16384), JSON header,
//!   then the raw HTTP-compatible body until QUIC FIN.
//! - Response: 2-byte big-endian HTTP status, then response bytes until FIN.
//! - Truncation or reset in either direction is an error, never a successful
//!   response.
//!
//! Safety rules:
//! - Only the read-only scheduler GETs (`status`, `server_certificate`) are
//!   ever attempted as 0-RTT early data, and a rejected early attempt is
//!   retried exactly once after the handshake completes.
//! - Mutations (`alloc_job`, `submit_toolchain`, `run_job`) are written only
//!   after the handshake is confirmed and are never retried, replayed or
//!   re-submitted.
//! - Nothing falls back to HTTP after a QUIC failure.
//!
//! Resource policy: one endpoint per client, at most 64 concurrent
//! bidirectional streams per connection, bounded per-stream and connection
//! flow-control windows, a handshake deadline and the same whole-RPC deadline
//! the HTTP transport uses. Overload therefore blocks on QUIC flow control and
//! eventually fails the RPC instead of buffering unbounded work.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine;
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt};

use crate::errors::*;

/// ALPN identifier shared with the gateway's QUIC listener.
pub const ALPN: &[u8] = b"billdfaster/1";

/// Wire schema version carried in every request header and in discovery.
const WIRE_VERSION: u8 = 1;

/// Absolute header bound from the wire contract.
const MAX_HEADER_LEN: usize = 16 * 1024;

/// Body caps from the wire contract.
const SCHEDULER_BODY_CAP: u64 = 64 * 1024;
const WORKER_BODY_CAP: u64 = 8 * 1024 * 1024 * 1024;

/// Response caps. Scheduler replies are bounded by the scheduler's own 64 KiB
/// encoder; worker replies share the transport's 8 GiB cap.
const SCHEDULER_RESPONSE_CAP: u64 = 1024 * 1024;
const WORKER_RESPONSE_CAP: u64 = 8 * 1024 * 1024 * 1024;

/// Discovery bounds: verified HTTPS, no proxy, bounded response.
const DISCOVERY_RESPONSE_CAP: usize = 16 * 1024;
const DISCOVERY_TIMEOUT_SECS: u64 = 10;
const DISCOVERY_CONNECT_TIMEOUT_SECS: u64 = 5;

/// Deadline for establishing (and confirming) a QUIC connection.
const HANDSHAKE_TIMEOUT_SECS: u64 = 10;

/// Whole-RPC deadline; mirrors the HTTP transport's request timeout so long
/// worker compiles keep the same budget on either transport.
const REQUEST_TIMEOUT_SECS: u64 = 1200;

/// Streaming chunk for request bodies.
const STREAM_CHUNK_BYTES: usize = 64 * 1024;

/// Application error code used when the client aborts a request stream.
const CLIENT_ABORT_CODE: u32 = 1;

/// Bounded credential/path field sizes, matching the gateway's own checks.
const MAX_PATH_BYTES: usize = 512;
const MAX_TOKEN_BYTES: usize = 512;
const MAX_AUTHORIZATION_BYTES: usize = 4096;

/// Connection resource policy. All bounds are finite.
const MAX_CONCURRENT_BIDI_STREAMS: u32 = 64;
const STREAM_RECEIVE_WINDOW: u32 = 16 * 1024 * 1024;
const CONNECTION_RECEIVE_WINDOW: u32 = 64 * 1024 * 1024;
const SEND_WINDOW: u64 = 16 * 1024 * 1024;
const CONNECTION_IDLE_TIMEOUT_SECS: u64 = 120;
const KEEP_ALIVE_INTERVAL_SECS: u64 = 30;

/// Trust material for the gateway's QUIC listener. Served by `GET /v1/quic`
/// (authenticated with the scheduler client token) or supplied directly by
/// tests and local wiring.
#[derive(Clone, Debug)]
pub struct Descriptor {
    pub port: u16,
    pub server_name: String,
    pub certificate_der: Vec<u8>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DiscoveryResponse {
    version: u8,
    port: u16,
    server_name: String,
    certificate_der: String,
}

#[derive(Serialize)]
struct RequestHeader<'a> {
    version: u8,
    target: Option<String>,
    method: &'a str,
    path: &'a str,
    client_token: &'a str,
    authorization: Option<&'a str>,
    content_length: Option<u64>,
}

/// HTTP method of a QUIC request. Only [`Method::Get`] scheduler requests are
/// replay-safe enough to be attempted as 0-RTT early data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Method {
    Get,
    Post,
}

impl Method {
    fn as_str(self) -> &'static str {
        match self {
            Method::Get => "GET",
            Method::Post => "POST",
        }
    }
}

/// Request body: empty (GET), in-memory (alloc/run-job payloads), or streamed
/// with a declared length (toolchain uploads).
pub enum Body {
    Empty,
    Bytes(Vec<u8>),
    Stream {
        reader: Box<dyn AsyncRead + Send + Unpin>,
        len: u64,
    },
}

impl Body {
    fn len(&self) -> u64 {
        match self {
            Body::Empty => 0,
            Body::Bytes(bytes) => bytes.len() as u64,
            Body::Stream { len, .. } => *len,
        }
    }
}

/// One wire request. `target` selects the gateway's scheduler (`None`) or a
/// registered worker's advertised relay address (`Some`).
pub struct Request {
    pub target: Option<SocketAddr>,
    pub method: Method,
    pub path: String,
    pub authorization: Option<String>,
    pub body: Body,
}

impl Request {
    /// Read-only scheduler requests are the only replay-safe shape allowed to
    /// use 0-RTT early data.
    fn is_read_only(&self) -> bool {
        self.method == Method::Get && self.target.is_none()
    }
}

/// One wire response: HTTP-compatible status plus the response body bytes.
pub struct Response {
    pub status: u16,
    pub body: Vec<u8>,
}

/// Non-sensitive transport counters, exposed for diagnostics and tests.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    pub connections_opened: u64,
    pub requests_sent: u64,
    pub zero_rtt_attempts: u64,
    pub zero_rtt_accepted: u64,
    pub zero_rtt_rejected: u64,
}

#[derive(Default)]
struct Counters {
    connections_opened: AtomicU64,
    requests_sent: AtomicU64,
    zero_rtt_attempts: AtomicU64,
    zero_rtt_accepted: AtomicU64,
    zero_rtt_rejected: AtomicU64,
}

impl Counters {
    fn snapshot(&self) -> Stats {
        Stats {
            connections_opened: self.connections_opened.load(Ordering::Relaxed),
            requests_sent: self.requests_sent.load(Ordering::Relaxed),
            zero_rtt_attempts: self.zero_rtt_attempts.load(Ordering::Relaxed),
            zero_rtt_accepted: self.zero_rtt_accepted.load(Ordering::Relaxed),
            zero_rtt_rejected: self.zero_rtt_rejected.load(Ordering::Relaxed),
        }
    }
}

/// Shared, lazily created transport state. Created once per client inside the
/// daemon's Tokio runtime and never replaced, so the rustls session store and
/// the connection pool survive certificate updates and RPC failures.
struct State {
    endpoint: quinn::Endpoint,
    client_config: quinn::ClientConfig,
    addr: SocketAddr,
    server_name: String,
    connect_lock: tokio::sync::Mutex<()>,
    connection: tokio::sync::Mutex<Option<quinn::Connection>>,
}

impl State {
    async fn live_connection(&self) -> Option<quinn::Connection> {
        let connection = self.connection.lock().await;
        match connection.as_ref() {
            Some(connection) if connection.close_reason().is_none() => Some(connection.clone()),
            _ => None,
        }
    }

    async fn store_connection(&self, connection: quinn::Connection) {
        *self.connection.lock().await = Some(connection);
    }

    fn start_connect(&self) -> Result<quinn::Connecting> {
        self.endpoint
            .connect_with(self.client_config.clone(), self.addr, &self.server_name)
            .with_context(|| format!("failed to start QUIC connection to {}", self.server_name))
    }
}

/// A lazy, single-endpoint QUIC transport for one dist client.
pub struct QuicClient {
    scheduler_url: reqwest::Url,
    auth_token: String,
    state: tokio::sync::Mutex<Option<Arc<State>>>,
    /// Direct trust material; when set, discovery over HTTPS is skipped.
    descriptor: Mutex<Option<Descriptor>>,
    counters: Counters,
}

impl QuicClient {
    /// Create a client that discovers the gateway descriptor over HTTPS on
    /// first use. Performs no I/O until the first request.
    pub fn new(scheduler_url: reqwest::Url, auth_token: String) -> Self {
        Self::build(scheduler_url, auth_token, None)
    }

    /// Create a client that trusts `descriptor` and never performs discovery.
    /// Used by loopback tests and direct wiring.
    pub fn from_descriptor(
        scheduler_url: reqwest::Url,
        auth_token: String,
        descriptor: Descriptor,
    ) -> Self {
        Self::build(scheduler_url, auth_token, Some(descriptor))
    }

    fn build(
        scheduler_url: reqwest::Url,
        auth_token: String,
        descriptor: Option<Descriptor>,
    ) -> Self {
        Self {
            scheduler_url,
            auth_token,
            state: tokio::sync::Mutex::new(None),
            descriptor: Mutex::new(descriptor),
            counters: Counters::default(),
        }
    }

    /// Snapshot of the transport counters.
    pub fn stats(&self) -> Stats {
        self.counters.snapshot()
    }

    /// Perform one RPC, bounded by the same whole-request deadline the HTTP
    /// transport applies.
    pub async fn request(&self, request: Request) -> Result<Response> {
        let deadline = Duration::from_secs(REQUEST_TIMEOUT_SECS);
        match tokio::time::timeout(deadline, self.request_inner(request)).await {
            Ok(result) => result,
            Err(_) => Err(anyhow!(
                "QUIC request to {} timed out after {}s",
                self.scheduler_url,
                REQUEST_TIMEOUT_SECS
            )),
        }
    }

    async fn request_inner(&self, mut request: Request) -> Result<Response> {
        self.validate(&request)?;
        let state = self.state().await?;
        self.counters.requests_sent.fetch_add(1, Ordering::Relaxed);
        if let Some(connection) = state.live_connection().await {
            return Self::round_trip(&connection, &self.auth_token, &mut request).await;
        }
        if request.is_read_only() {
            return self.connect_read_only(&state, &mut request).await;
        }
        let connection = self.connect_handshaked(&state).await?;
        Self::round_trip(&connection, &self.auth_token, &mut request).await
    }

    /// Validate everything the gateway would reject anyway, before a stream is
    /// even opened, so local mistakes fail loudly instead of becoming wire
    /// errors.
    fn validate(&self, request: &Request) -> Result<()> {
        let path = request.path.as_str();
        if path.len() <= 1
            || path.len() > MAX_PATH_BYTES
            || !path.starts_with('/')
            || path
                .bytes()
                .any(|byte| !(0x21..=0x7e).contains(&byte) || byte == b'?' || byte == b'#')
        {
            bail!("invalid QUIC request path {:?}", path);
        }
        if self.auth_token.is_empty() || self.auth_token.len() > MAX_TOKEN_BYTES {
            bail!("scheduler client token is empty or too long for QUIC");
        }
        match request.target {
            None => {
                if request.body.len() > SCHEDULER_BODY_CAP {
                    bail!(
                        "scheduler QUIC request body of {} bytes exceeds the {} byte cap",
                        request.body.len(),
                        SCHEDULER_BODY_CAP
                    );
                }
            }
            Some(_) => {
                if request.method != Method::Post {
                    bail!("worker QUIC requests must be POST");
                }
                if request.body.len() > WORKER_BODY_CAP {
                    bail!(
                        "worker QUIC request body of {} bytes exceeds the {} byte cap",
                        request.body.len(),
                        WORKER_BODY_CAP
                    );
                }
                let authorization = request
                    .authorization
                    .as_deref()
                    .context("worker QUIC requests require a job bearer")?;
                if authorization.len() > MAX_AUTHORIZATION_BYTES
                    || !authorization.starts_with("Bearer ")
                    || authorization
                        .bytes()
                        .any(|byte| byte < 0x20 || byte == 0x7f)
                {
                    bail!("worker QUIC job bearer is malformed");
                }
            }
        }
        Ok(())
    }

    /// The shared transport state, created on first use inside the daemon's
    /// runtime. Initialisation failures are never cached.
    async fn state(&self) -> Result<Arc<State>> {
        let mut guard = self.state.lock().await;
        if let Some(state) = guard.as_ref() {
            return Ok(state.clone());
        }
        let state = Arc::new(self.build_state().await?);
        *guard = Some(state.clone());
        Ok(state)
    }

    async fn build_state(&self) -> Result<State> {
        // Take the lock only for the clone: a `std::sync` guard must never be
        // held across the discovery await below.
        let descriptor = self.descriptor.lock().unwrap().clone();
        let descriptor = match descriptor {
            Some(descriptor) => descriptor,
            None => self.fetch_descriptor().await?,
        };
        let host = self
            .scheduler_url
            .host_str()
            .context("scheduler url has no host")?
            .to_owned();
        if descriptor.server_name != host {
            bail!(
                "QUIC descriptor server name {:?} does not match scheduler host {:?}",
                descriptor.server_name,
                host
            );
        }
        if descriptor.certificate_der.is_empty() {
            bail!("QUIC descriptor carries no certificate");
        }
        if descriptor.port == 0 {
            bail!("QUIC descriptor carries no usable port");
        }
        // Trust exactly the descriptor certificate as a root; ordinary rustls
        // signature and name verification does the rest.
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(rustls::pki_types::CertificateDer::from(
                descriptor.certificate_der.clone(),
            ))
            .context("QUIC descriptor certificate is not a valid trust anchor")?;
        // The crate graph already enables another rustls provider for reqwest,
        // so pick *ring* explicitly instead of relying on a crate default.
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut crypto = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .context("failed to configure QUIC TLS versions")?
            .with_root_certificates(roots)
            .with_no_client_auth();
        crypto.alpn_protocols = vec![ALPN.to_vec()];
        // 0-RTT is attempted only for read-only scheduler GETs; the transport
        // gates mutations behind handshake completion below.
        crypto.enable_early_data = true;
        let quic_crypto = quinn::crypto::rustls::QuicClientConfig::try_from(crypto)
            .context("failed to build QUIC client TLS configuration")?;
        let mut client_config = quinn::ClientConfig::new(Arc::new(quic_crypto));
        client_config.transport_config(Arc::new(transport_config()?));
        let addr = resolve_ipv4(&host, descriptor.port).await?;
        let socket =
            std::net::UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))
                .context("failed to bind QUIC client socket")?;
        socket
            .set_nonblocking(true)
            .context("failed to make QUIC client socket non-blocking")?;
        let endpoint = quinn::Endpoint::new(
            quinn::EndpointConfig::default(),
            None,
            socket,
            Arc::new(quinn::TokioRuntime),
        )
        .context("failed to create QUIC endpoint")?;
        Ok(State {
            endpoint,
            client_config,
            addr,
            server_name: descriptor.server_name,
            connect_lock: tokio::sync::Mutex::new(()),
            connection: tokio::sync::Mutex::new(None),
        })
    }

    /// `GET /v1/quic` over ordinary verified HTTPS without proxy usage.
    async fn fetch_descriptor(&self) -> Result<Descriptor> {
        let url = self
            .scheduler_url
            .join("/v1/quic")
            .context("failed to build the QUIC discovery url")?;
        match url.scheme() {
            "https" => {}
            "http" if is_loopback_host(&url) => warn!(
                "QUIC discovery for {} uses plaintext HTTP on a loopback address",
                url.host_str().unwrap_or_default()
            ),
            scheme => bail!(
                "QUIC discovery requires HTTPS, scheduler url scheme is {:?}",
                scheme
            ),
        }
        let mut builder = reqwest::ClientBuilder::new()
            .no_proxy()
            // The descriptor must come from the configured scheduler origin
            // itself; a redirect could move it to an unrelated (or plaintext)
            // origin, so no redirect is ever followed.
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(DISCOVERY_CONNECT_TIMEOUT_SECS))
            .timeout(Duration::from_secs(DISCOVERY_TIMEOUT_SECS));
        if url.scheme() == "https" {
            builder = builder.https_only(true);
        }
        let client = builder
            .build()
            .context("failed to create the QUIC discovery client")?;
        let response = client
            .get(url)
            .bearer_auth(&self.auth_token)
            .send()
            .await
            .context("QUIC discovery request failed")?;
        let status = response.status();
        let body = read_bounded(response, DISCOVERY_RESPONSE_CAP).await?;
        if !status.is_success() {
            bail!(
                "QUIC discovery failed: Error {}: {}",
                status.as_u16(),
                String::from_utf8_lossy(&body)
            );
        }
        let discovery: DiscoveryResponse =
            serde_json::from_slice(&body).context("failed to parse the QUIC discovery response")?;
        if discovery.version != WIRE_VERSION {
            bail!(
                "QUIC discovery returned unsupported wire version {}",
                discovery.version
            );
        }
        let certificate_der = base64::engine::general_purpose::STANDARD
            .decode(discovery.certificate_der.as_bytes())
            .context("QUIC discovery certificate is not valid base64")?;
        if certificate_der.is_empty() {
            bail!("QUIC discovery returned an empty certificate");
        }
        Ok(Descriptor {
            port: discovery.port,
            server_name: discovery.server_name,
            certificate_der,
        })
    }

    /// Establish (or reuse) a connection whose handshake is confirmed. Used
    /// for every mutation and for any request when no connection is live.
    async fn connect_handshaked(&self, state: &State) -> Result<quinn::Connection> {
        if let Some(connection) = state.live_connection().await {
            return Ok(connection);
        }
        let _guard = state.connect_lock.lock().await;
        if let Some(connection) = state.live_connection().await {
            return Ok(connection);
        }
        let connecting = state.start_connect()?;
        let connection =
            tokio::time::timeout(Duration::from_secs(HANDSHAKE_TIMEOUT_SECS), connecting)
                .await
                .map_err(|_| {
                    anyhow!(
                        "QUIC handshake with {} timed out after {}s",
                        state.server_name,
                        HANDSHAKE_TIMEOUT_SECS
                    )
                })?
                .context("QUIC handshake failed")?;
        self.publish_connection(state, &connection).await;
        Ok(connection)
    }

    /// Read-only path that may send the request as 0-RTT early data. A
    /// rejection (or an unavailable session) is retried exactly once after the
    /// handshake completes; every other error is returned as-is.
    async fn connect_read_only(&self, state: &State, request: &mut Request) -> Result<Response> {
        if let Some(connection) = state.live_connection().await {
            return Self::round_trip(&connection, &self.auth_token, request).await;
        }
        let _guard = state.connect_lock.lock().await;
        if let Some(connection) = state.live_connection().await {
            return Self::round_trip(&connection, &self.auth_token, request).await;
        }
        let connecting = state.start_connect()?;
        match connecting.into_0rtt() {
            Ok((connection, accepted)) => {
                self.counters
                    .zero_rtt_attempts
                    .fetch_add(1, Ordering::Relaxed);
                // Drive the early request and the resumption verdict
                // concurrently. The verdict has its own deadline and, once the
                // handshake is confirmed, publishes the connection and
                // releases the connect lock immediately, so other RPCs are
                // never serialized behind this request. The request itself
                // stays on the RPC deadline.
                let publish = async {
                    let verdict =
                        tokio::time::timeout(Duration::from_secs(HANDSHAKE_TIMEOUT_SECS), accepted)
                            .await;
                    let mut published = false;
                    if verdict.is_ok() {
                        published = self.publish_connection(state, &connection).await;
                    } else {
                        // The handshake will never confirm: close the
                        // connection so a request still waiting on it fails
                        // instead of burning the whole RPC deadline.
                        connection.close(
                            quinn::VarInt::from_u32(CLIENT_ABORT_CODE),
                            b"handshake deadline",
                        );
                    }
                    drop(_guard);
                    (verdict.ok(), published)
                };
                let (result, (verdict, published)) = futures::join!(
                    Self::round_trip(&connection, &self.auth_token, request),
                    publish
                );
                if verdict.is_none() {
                    // The handshake deadline elapsed (the request cannot have
                    // been processed on a connection that never confirmed).
                    return Err(match result {
                        Ok(_) => anyhow!(
                            "QUIC handshake with {} timed out after {}s",
                            state.server_name,
                            HANDSHAKE_TIMEOUT_SECS
                        ),
                        Err(error) => error.context(format!(
                            "QUIC handshake with {} timed out after {}s",
                            state.server_name, HANDSHAKE_TIMEOUT_SECS
                        )),
                    });
                }
                match result {
                    Ok(response) => {
                        self.counters
                            .zero_rtt_accepted
                            .fetch_add(1, Ordering::Relaxed);
                        if !published {
                            // The early response arrived before the verdict was
                            // observed: make the confirmed connection reusable.
                            self.publish_connection(state, &connection).await;
                        }
                        Ok(response)
                    }
                    Err(error) => {
                        let rejected = is_zero_rtt_rejected(&error)
                            || (verdict == Some(false) && connection.close_reason().is_none());
                        if rejected {
                            self.counters
                                .zero_rtt_rejected
                                .fetch_add(1, Ordering::Relaxed);
                            // The server dropped the early data but completed
                            // the handshake. Retry this read-only request on a
                            // fresh, fully protected stream; a mutation would
                            // never reach this path.
                            let response =
                                Self::round_trip(&connection, &self.auth_token, request).await?;
                            if !published {
                                self.publish_connection(state, &connection).await;
                            }
                            Ok(response)
                        } else {
                            Err(error)
                        }
                    }
                }
            }
            Err(connecting) => {
                let connection =
                    tokio::time::timeout(Duration::from_secs(HANDSHAKE_TIMEOUT_SECS), connecting)
                        .await
                        .map_err(|_| {
                            anyhow!(
                                "QUIC handshake with {} timed out after {}s",
                                state.server_name,
                                HANDSHAKE_TIMEOUT_SECS
                            )
                        })?
                        .context("QUIC handshake failed")?;
                self.publish_connection(state, &connection).await;
                // The connection is confirmed and stored; other requests may
                // use it in parallel with this round trip.
                drop(_guard);
                Self::round_trip(&connection, &self.auth_token, request).await
            }
        }
    }

    /// Store a healthy connection for reuse. Returns whether it was published.
    async fn publish_connection(&self, state: &State, connection: &quinn::Connection) -> bool {
        if connection.close_reason().is_some() {
            return false;
        }
        self.counters
            .connections_opened
            .fetch_add(1, Ordering::Relaxed);
        state.store_connection(connection.clone()).await;
        true
    }

    /// One request/response exchange on a fresh bidirectional stream.
    async fn round_trip(
        connection: &quinn::Connection,
        client_token: &str,
        request: &mut Request,
    ) -> Result<Response> {
        let (send, mut recv) = connection
            .open_bi()
            .await
            .context("failed to open a QUIC stream")?;
        // Any error or cancellation before `disarm` resets the stream instead
        // of letting quinn's implicit finish turn a partial upload into a
        // complete-looking request.
        let mut abort = AbortOnDrop::new(send);
        let content_length = match &request.body {
            Body::Empty => None,
            body => Some(body.len()),
        };
        let header = RequestHeader {
            version: WIRE_VERSION,
            target: request.target.map(|addr| addr.to_string()),
            method: request.method.as_str(),
            path: request.path.as_str(),
            client_token,
            authorization: request.authorization.as_deref(),
            content_length,
        };
        let encoded =
            serde_json::to_vec(&header).context("failed to encode the QUIC request header")?;
        if encoded.is_empty() || encoded.len() > MAX_HEADER_LEN {
            bail!("QUIC request header length {} out of range", encoded.len());
        }
        abort
            .stream()
            .write_all(&(encoded.len() as u32).to_be_bytes())
            .await
            .context("failed to write the QUIC request header length")?;
        abort
            .stream()
            .write_all(&encoded)
            .await
            .context("failed to write the QUIC request header")?;
        let written = match &mut request.body {
            Body::Empty => 0,
            Body::Bytes(bytes) => {
                abort
                    .stream()
                    .write_all(bytes)
                    .await
                    .context("failed to write the QUIC request body")?;
                bytes.len() as u64
            }
            Body::Stream { reader, len } => {
                let len = *len;
                let send = abort.stream();
                stream_body(send, reader.as_mut(), len).await?
            }
        };
        // Validate the bytes consumed before the stream can be finished: a
        // mismatch must abort the upload, never look complete.
        if let Some(declared) = content_length {
            if declared != written {
                bail!(
                    "QUIC request body declared {} bytes but produced {}",
                    declared,
                    written
                );
            }
        }
        abort
            .stream()
            .finish()
            .context("failed to finish the QUIC request stream")?;
        abort.disarm();

        let mut status_bytes = [0u8; 2];
        recv.read_exact(&mut status_bytes)
            .await
            .context("failed to read the QUIC response status")?;
        let status = u16::from_be_bytes(status_bytes);
        let cap = if request.target.is_some() {
            WORKER_RESPONSE_CAP
        } else {
            SCHEDULER_RESPONSE_CAP
        };
        let body = recv
            .read_to_end(read_cap(cap))
            .await
            .context("failed to read the QUIC response body")?;
        Ok(Response { status, body })
    }

    /// Test hook: trust `descriptor` instead of running HTTPS discovery.
    #[cfg(test)]
    pub(crate) fn set_descriptor(&self, descriptor: Descriptor) {
        *self.descriptor.lock().unwrap() = Some(descriptor);
    }

    /// Test hook: close the cached connection so the next read-only request
    /// has to establish a new one (resumption and 0-RTT coverage).
    #[cfg(test)]
    pub(crate) async fn close_cached_connection(&self) {
        let state = self.state.lock().await.clone();
        if let Some(state) = state {
            let connection = state.connection.lock().await.take();
            if let Some(connection) = connection {
                connection.close(0u32.into(), b"test close");
            }
        }
    }
}

fn transport_config() -> Result<quinn::TransportConfig> {
    let mut transport = quinn::TransportConfig::default();
    transport.max_concurrent_bidi_streams(quinn::VarInt::from_u32(MAX_CONCURRENT_BIDI_STREAMS));
    transport.stream_receive_window(quinn::VarInt::from_u32(STREAM_RECEIVE_WINDOW));
    transport.receive_window(quinn::VarInt::from_u32(CONNECTION_RECEIVE_WINDOW));
    transport.send_window(SEND_WINDOW);
    transport.max_idle_timeout(Some(
        Duration::from_secs(CONNECTION_IDLE_TIMEOUT_SECS)
            .try_into()
            .context("invalid QUIC idle timeout")?,
    ));
    transport.keep_alive_interval(Some(Duration::from_secs(KEEP_ALIVE_INTERVAL_SECS)));
    Ok(transport)
}

/// Owns the request send stream while the request is being handed over.
///
/// Dropping a quinn `SendStream` implicitly finishes it (a clean FIN), which
/// would let the gateway treat a locally failed or cancelled upload as a
/// complete, valid request — and dispatch a mutation the client believes
/// failed. The guard therefore resets the stream unless it was explicitly
/// disarmed after a successful `finish()`.
struct AbortOnDrop {
    send: Option<quinn::SendStream>,
}

impl AbortOnDrop {
    fn new(send: quinn::SendStream) -> Self {
        Self { send: Some(send) }
    }

    fn stream(&mut self) -> &mut quinn::SendStream {
        self.send.as_mut().expect("QUIC request stream is armed")
    }

    /// The request was written and finished: the stream must not be reset.
    fn disarm(&mut self) {
        self.send = None;
    }
}

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        if let Some(mut send) = self.send.take() {
            let _ = send.reset(quinn::VarInt::from_u32(CLIENT_ABORT_CODE));
        }
    }
}

/// Stream a request body in bounded chunks, refusing to produce more bytes
/// than the declared length.
async fn stream_body(
    send: &mut quinn::SendStream,
    reader: &mut (dyn AsyncRead + Send + Unpin),
    declared: u64,
) -> Result<u64> {
    let mut buffer = vec![0u8; STREAM_CHUNK_BYTES];
    let mut written = 0u64;
    loop {
        let read = reader
            .read(&mut buffer)
            .await
            .context("failed to read the QUIC request body source")?;
        if read == 0 {
            break;
        }
        written += read as u64;
        if written > declared {
            bail!(
                "QUIC request body source produced more than the declared {} bytes",
                declared
            );
        }
        send.write_all(&buffer[..read])
            .await
            .context("failed to stream the QUIC request body")?;
    }
    Ok(written)
}

/// The gateway rejects early data for unreadable sessions; that rejection is
/// the only error that may be retried, and only for read-only requests.
fn is_zero_rtt_rejected(error: &Error) -> bool {
    error.chain().any(|cause| {
        matches!(
            cause.downcast_ref::<quinn::WriteError>(),
            Some(quinn::WriteError::ZeroRttRejected)
        ) || matches!(
            cause.downcast_ref::<quinn::ReadError>(),
            Some(quinn::ReadError::ZeroRttRejected)
        ) || matches!(
            cause.downcast_ref::<quinn::ReadExactError>(),
            Some(quinn::ReadExactError::ReadError(
                quinn::ReadError::ZeroRttRejected
            ))
        )
    })
}

/// Resolve the scheduler host to an IPv4 address: public UDP on Fly is only
/// served on the dedicated IPv4 address.
async fn resolve_ipv4(host: &str, port: u16) -> Result<SocketAddr> {
    let addrs = tokio::net::lookup_host((host, port))
        .await
        .with_context(|| format!("failed to resolve the QUIC scheduler host {host:?}"))?;
    addrs
        .filter(SocketAddr::is_ipv4)
        .next()
        .with_context(|| format!("QUIC scheduler host {host:?} has no IPv4 address"))
}

fn is_loopback_host(url: &reqwest::Url) -> bool {
    match url.host() {
        Some(url::Host::Ipv4(addr)) => addr.is_loopback(),
        Some(url::Host::Ipv6(addr)) => addr.is_loopback(),
        Some(url::Host::Domain(domain)) => domain.eq_ignore_ascii_case("localhost"),
        None => false,
    }
}

fn read_cap(cap: u64) -> usize {
    usize::try_from(cap).unwrap_or(usize::MAX)
}

/// Read a whole response body with a hard cap, used by discovery.
async fn read_bounded(response: reqwest::Response, cap: usize) -> Result<Vec<u8>> {
    if let Some(length) = response.content_length() {
        if length > cap as u64 {
            bail!("response of {} bytes exceeds the {} byte cap", length, cap);
        }
    }
    let mut body = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.context("failed to read the response body")?;
        if body.len() + chunk.len() > cap {
            bail!("response exceeds the {} byte cap", cap);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

#[cfg(test)]
pub(crate) mod test_fixture {
    //! Loopback QUIC gateway used by the client tests. It speaks wire v1
    //! exactly like the real gateway: bounded header, declared body length,
    //! 2-byte status, response bytes, FIN. Response behaviour is selectable so
    //! tests can exercise reset/truncation and HTTPS-style error statuses.

    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, AtomicU8};

    pub(crate) const MODE_OK: u8 = 0;
    pub(crate) const MODE_HTTP_ERROR: u8 = 1;
    pub(crate) const MODE_RESET_AFTER_STATUS: u8 = 2;
    pub(crate) const MODE_RESET_IMMEDIATELY: u8 = 3;

    #[derive(Clone, Debug)]
    pub(crate) struct RecordedRequest {
        pub(crate) version: u8,
        pub(crate) target: Option<String>,
        pub(crate) method: String,
        pub(crate) path: String,
        pub(crate) client_token: String,
        pub(crate) authorization: Option<String>,
        pub(crate) content_length: Option<u64>,
        pub(crate) body: Vec<u8>,
    }

    #[derive(Deserialize, Serialize)]
    #[serde(deny_unknown_fields)]
    struct WireHeader {
        version: u8,
        target: Option<String>,
        method: String,
        path: String,
        client_token: String,
        authorization: Option<String>,
        content_length: Option<u64>,
    }

    pub(crate) type Responder = Arc<dyn Fn(&RecordedRequest) -> (u16, Vec<u8>) + Send + Sync>;

    /// Minimal DER-to-PEM encoder: rcgen is built without its PEM feature, and
    /// `reqwest::Certificate::from_pem` needs PEM text for the certificate
    /// update path.
    pub(crate) fn der_to_pem(der: &[u8]) -> String {
        let encoded = base64::engine::general_purpose::STANDARD.encode(der);
        let mut pem = String::from("-----BEGIN CERTIFICATE-----\n");
        for line in encoded.as_bytes().chunks(64) {
            pem.push_str(std::str::from_utf8(line).expect("base64 output is ASCII"));
            pem.push('\n');
        }
        pem.push_str("-----END CERTIFICATE-----\n");
        pem
    }

    #[derive(Debug, Default)]
    struct SessionStore {
        sessions: Mutex<HashMap<Vec<u8>, Vec<u8>>>,
        drop_lookups: AtomicBool,
    }

    impl rustls::server::StoresServerSessions for SessionStore {
        fn put(&self, key: Vec<u8>, value: Vec<u8>) -> bool {
            self.sessions.lock().unwrap().insert(key, value);
            true
        }
        fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
            if self.drop_lookups.load(Ordering::SeqCst) {
                return None;
            }
            self.sessions.lock().unwrap().get(key).cloned()
        }
        fn take(&self, key: &[u8]) -> Option<Vec<u8>> {
            if self.drop_lookups.load(Ordering::SeqCst) {
                return None;
            }
            self.sessions.lock().unwrap().remove(key)
        }
        fn can_cache(&self) -> bool {
            // Capacity is unbounded and `put` always stores, so tickets keep
            // being issued even while lookups are dropped (a restarted server
            // that lost the key material still hands out fresh tickets).
            true
        }
    }

    struct Shared {
        connections: AtomicU64,
        streams: AtomicU64,
        requests: Mutex<Vec<RecordedRequest>>,
        mode: AtomicU8,
        sessions: Arc<SessionStore>,
    }

    /// A loopback QUIC server that speaks wire v1 with a real rcgen
    /// certificate; the client trusts it through a [`Descriptor`].
    pub(crate) struct Fixture {
        pub(crate) port: u16,
        pub(crate) server_name: String,
        pub(crate) certificate_der: Vec<u8>,
        shared: Arc<Shared>,
        endpoint: quinn::Endpoint,
        accept: tokio::task::JoinHandle<()>,
    }

    impl Fixture {
        pub(crate) async fn start() -> Fixture {
            Self::start_with(None).await
        }

        pub(crate) async fn start_with(responder: Option<Responder>) -> Fixture {
            let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
                .expect("failed to generate the fixture certificate");
            let certificate_der = certified.cert.der().to_vec();
            let key = rustls::pki_types::PrivateKeyDer::Pkcs8(
                rustls::pki_types::PrivatePkcs8KeyDer::from(certified.signing_key.serialize_der()),
            );
            let provider = Arc::new(rustls::crypto::ring::default_provider());
            let mut crypto = rustls::ServerConfig::builder_with_provider(provider)
                .with_protocol_versions(&[&rustls::version::TLS13])
                .expect("ring supports TLS 1.3")
                .with_no_client_auth()
                .with_single_cert(
                    vec![rustls::pki_types::CertificateDer::from(
                        certificate_der.clone(),
                    )],
                    key,
                )
                .expect("failed to build the fixture server certificate");
            crypto.alpn_protocols = vec![ALPN.to_vec()];
            crypto.max_early_data_size = u32::MAX;
            let sessions = Arc::new(SessionStore::default());
            crypto.session_storage = sessions.clone();
            let server_config = quinn::ServerConfig::with_crypto(Arc::new(
                quinn::crypto::rustls::QuicServerConfig::try_from(crypto)
                    .expect("failed to build the fixture QUIC server config"),
            ));
            let endpoint = quinn::Endpoint::server(
                server_config,
                "127.0.0.1:0".parse().expect("valid loopback address"),
            )
            .expect("failed to bind the fixture QUIC endpoint");
            let port = endpoint
                .local_addr()
                .expect("fixture endpoint has a local address")
                .port();
            let shared = Arc::new(Shared {
                connections: AtomicU64::new(0),
                streams: AtomicU64::new(0),
                requests: Mutex::new(Vec::new()),
                mode: AtomicU8::new(MODE_OK),
                sessions,
            });
            let responder = responder.unwrap_or_else(|| {
                Arc::new(|request: &RecordedRequest| {
                    (
                        200,
                        format!("{}:{}", request.path, request.body.len()).into_bytes(),
                    )
                })
            });
            let accept = tokio::spawn(service(endpoint.clone(), shared.clone(), responder));
            Fixture {
                port,
                server_name: "localhost".to_string(),
                certificate_der,
                shared,
                endpoint,
                accept,
            }
        }

        pub(crate) fn descriptor(&self) -> Descriptor {
            Descriptor {
                port: self.port,
                server_name: self.server_name.clone(),
                certificate_der: self.certificate_der.clone(),
            }
        }

        pub(crate) fn request_log(&self) -> Vec<RecordedRequest> {
            self.shared.requests.lock().unwrap().clone()
        }

        pub(crate) fn connection_count(&self) -> u64 {
            self.shared.connections.load(Ordering::SeqCst)
        }

        pub(crate) fn stream_count(&self) -> u64 {
            self.shared.streams.load(Ordering::SeqCst)
        }

        pub(crate) fn set_mode(&self, mode: u8) {
            self.shared.mode.store(mode, Ordering::SeqCst);
        }

        pub(crate) fn drop_session_lookups(&self, drop: bool) {
            // Simulates a restarted server that no longer recognizes tickets
            // issued by a previous process.
            self.shared
                .sessions
                .drop_lookups
                .store(drop, Ordering::SeqCst);
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            self.endpoint.close(0u32.into(), b"fixture shutdown");
            self.accept.abort();
        }
    }

    async fn service(endpoint: quinn::Endpoint, shared: Arc<Shared>, responder: Responder) {
        while let Some(incoming) = endpoint.accept().await {
            let shared = shared.clone();
            let responder = responder.clone();
            tokio::spawn(async move {
                let connection = match incoming.await {
                    Ok(connection) => connection,
                    Err(_) => return,
                };
                shared.connections.fetch_add(1, Ordering::SeqCst);
                loop {
                    match connection.accept_bi().await {
                        Ok((send, recv)) => {
                            shared.streams.fetch_add(1, Ordering::SeqCst);
                            tokio::spawn(handle_stream(
                                send,
                                recv,
                                shared.clone(),
                                responder.clone(),
                            ));
                        }
                        Err(_) => break,
                    }
                }
            });
        }
    }

    async fn handle_stream(
        mut send: quinn::SendStream,
        mut recv: quinn::RecvStream,
        shared: Arc<Shared>,
        responder: Responder,
    ) {
        let mode = shared.mode.load(Ordering::SeqCst);
        if mode == MODE_RESET_IMMEDIATELY {
            let _ = send.reset(quinn::VarInt::from_u32(2));
            return;
        }
        let request = match read_request(&mut recv).await {
            Ok(request) => request,
            Err(()) => {
                let _ = send.reset(quinn::VarInt::from_u32(1));
                return;
            }
        };
        shared.requests.lock().unwrap().push(request.clone());
        let (status, body) = if mode == MODE_HTTP_ERROR {
            (404, b"{\"error\":\"unknown route\"}".to_vec())
        } else {
            responder(&request)
        };
        if send.write_all(&status.to_be_bytes()).await.is_err() {
            return;
        }
        if send.write_all(&body).await.is_err() {
            return;
        }
        if mode == MODE_RESET_AFTER_STATUS {
            // Truncated response: reset instead of FIN, so the client must
            // treat the response as failed.
            let _ = send.reset(quinn::VarInt::from_u32(2));
        } else {
            let _ = send.finish();
        }
    }

    async fn read_request(
        recv: &mut quinn::RecvStream,
    ) -> std::result::Result<RecordedRequest, ()> {
        let mut prefix = [0u8; 4];
        recv.read_exact(&mut prefix).await.map_err(|_| ())?;
        let length = u32::from_be_bytes(prefix) as usize;
        if length == 0 || length > MAX_HEADER_LEN {
            return Err(());
        }
        let mut encoded = vec![0u8; length];
        recv.read_exact(&mut encoded).await.map_err(|_| ())?;
        let header: WireHeader = serde_json::from_slice(&encoded).map_err(|_| ())?;
        let body = match header.content_length {
            Some(length) if length <= WORKER_BODY_CAP => {
                let mut body = vec![0u8; length as usize];
                recv.read_exact(&mut body).await.map_err(|_| ())?;
                // The declared length must be exactly what the stream carried:
                // extra bytes, or a reset instead of a clean FIN, abort the
                // request. This mirrors the gateway's own validation.
                match recv.read(&mut [0u8; 1]).await {
                    Ok(None) => {}
                    Ok(Some(_)) | Err(_) => return Err(()),
                }
                body
            }
            None => recv.read_to_end(MAX_HEADER_LEN).await.map_err(|_| ())?,
            Some(_) => return Err(()),
        };
        Ok(RecordedRequest {
            version: header.version,
            target: header.target,
            method: header.method,
            path: header.path,
            client_token: header.client_token,
            authorization: header.authorization,
            content_length: header.content_length,
            body,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::test_fixture::{
        Fixture, MODE_HTTP_ERROR, MODE_OK, MODE_RESET_AFTER_STATUS, MODE_RESET_IMMEDIATELY,
    };
    use super::*;

    fn client(fixture: &Fixture) -> QuicClient {
        QuicClient::from_descriptor(
            reqwest::Url::parse("https://localhost").unwrap(),
            "scheduler-token".to_string(),
            fixture.descriptor(),
        )
    }

    fn status_request() -> Request {
        Request {
            target: None,
            method: Method::Get,
            path: "/api/v1/scheduler/status".to_string(),
            authorization: None,
            body: Body::Empty,
        }
    }

    fn alloc_request() -> Request {
        Request {
            target: None,
            method: Method::Post,
            path: "/api/v1/scheduler/alloc_job".to_string(),
            authorization: Some("Bearer scheduler-token".to_string()),
            body: Body::Bytes(b"alloc-body".to_vec()),
        }
    }

    /// `Response` intentionally has no `Debug`, so tests take the error out of
    /// the result explicitly instead of using `unwrap_err`.
    fn expect_error(result: Result<Response>) -> Error {
        match result {
            Ok(_) => panic!("expected the QUIC request to fail"),
            Err(error) => error,
        }
    }

    /// Drive the client until it attempts 0-RTT: that only happens once a
    /// session ticket has been stored and the connection is re-established.
    async fn await_resumption(client: &QuicClient) -> bool {
        for _ in 0..40 {
            let attempts = client.stats().zero_rtt_attempts;
            client.close_cached_connection().await;
            let response = client.request(status_request()).await.unwrap();
            assert_eq!(response.status, 200);
            if client.stats().zero_rtt_attempts > attempts {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        false
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn read_only_requests_reuse_one_connection() {
        let fixture = Fixture::start().await;
        let client = client(&fixture);
        for _ in 0..3 {
            let response = client.request(status_request()).await.unwrap();
            assert_eq!(response.status, 200);
            assert_eq!(response.body, b"/api/v1/scheduler/status:0");
        }
        assert_eq!(fixture.connection_count(), 1, "connections were reopened");
        assert_eq!(fixture.stream_count(), 3);
        assert_eq!(client.stats().connections_opened, 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn early_data_get_is_accepted_after_resumption() {
        let fixture = Fixture::start().await;
        let client = client(&fixture);
        assert!(await_resumption(&client).await, "no session was resumed");
        assert!(client.stats().zero_rtt_accepted >= 1);
        assert_eq!(client.stats().zero_rtt_rejected, 0);
        assert!(
            fixture.connection_count() >= 2,
            "no new connection was made"
        );
        assert_eq!(
            fixture.request_log().len(),
            client.stats().requests_sent as usize
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn rejected_early_data_retries_the_read_only_get_once() {
        let fixture = Fixture::start().await;
        let client = client(&fixture);
        assert!(await_resumption(&client).await, "no session was resumed");

        let rejected_before = client.stats().zero_rtt_rejected;
        // Drop the server's session state: tickets are now unknown, so early
        // data is rejected while the handshake still completes. The client
        // consumes a ticket on every attempt, so keep reconnecting until one
        // is presented again; fresh tickets keep being issued meanwhile.
        fixture.drop_session_lookups(true);
        let mut observed = false;
        for _ in 0..40 {
            let attempts = client.stats().zero_rtt_attempts;
            let requests = fixture.request_log().len() as u64;
            client.close_cached_connection().await;
            let response = client.request(status_request()).await.unwrap();
            assert_eq!(response.status, 200);
            if client.stats().zero_rtt_attempts > attempts {
                assert!(client.stats().zero_rtt_rejected > rejected_before);
                assert_eq!(
                    fixture.request_log().len() as u64,
                    requests + 1,
                    "rejected early data must be retried exactly once after the handshake"
                );
                observed = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(observed, "the client never presented a session ticket");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn mutations_never_use_early_data() {
        let fixture = Fixture::start().await;
        let client = client(&fixture);
        assert!(await_resumption(&client).await, "no session was resumed");

        client.close_cached_connection().await;
        let attempts_before = client.stats().zero_rtt_attempts;
        let response = client.request(alloc_request()).await.unwrap();
        assert_eq!(response.status, 200);
        assert_eq!(
            client.stats().zero_rtt_attempts,
            attempts_before,
            "a mutation must wait for the confirmed handshake"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn concurrent_requests_share_one_connection() {
        let fixture = Fixture::start().await;
        let client = client(&fixture);
        // Establish the connection first, then fan out.
        assert_eq!(client.request(status_request()).await.unwrap().status, 200);
        let responses =
            futures::future::join_all((0..8).map(|_| client.request(status_request()))).await;
        for response in responses {
            assert_eq!(response.unwrap().status, 200);
        }
        assert_eq!(fixture.connection_count(), 1, "connections were reopened");
        assert_eq!(fixture.stream_count(), 9);
        assert_eq!(fixture.request_log().len(), 9);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn streamed_worker_body_is_delivered_exactly() {
        let fixture = Fixture::start().await;
        let client = client(&fixture);
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("toolchain.tar");
        let payload: Vec<u8> = (0..3 * 1024 * 1024)
            .map(|index| (index % 251) as u8)
            .collect();
        std::fs::write(&path, &payload).unwrap();

        let worker: SocketAddr = "127.0.0.1:41000".parse().unwrap();
        let request = Request {
            target: Some(worker),
            method: Method::Post,
            path: "/api/v1/distserver/submit_toolchain/42".to_string(),
            authorization: Some("Bearer job-token".to_string()),
            body: Body::Stream {
                reader: Box::new(tokio::fs::File::open(&path).await.unwrap()),
                len: payload.len() as u64,
            },
        };
        let response = client.request(request).await.unwrap();
        assert_eq!(response.status, 200);

        let log = fixture.request_log();
        assert_eq!(log.len(), 1);
        assert_eq!(log[0].target.as_deref(), Some("127.0.0.1:41000"));
        assert_eq!(log[0].method, "POST");
        assert_eq!(log[0].client_token, "scheduler-token");
        assert_eq!(log[0].authorization.as_deref(), Some("Bearer job-token"));
        assert_eq!(log[0].content_length, Some(payload.len() as u64));
        assert_eq!(log[0].body, payload);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn oversize_streamed_body_is_aborted_not_completed() {
        let fixture = Fixture::start().await;
        let client = client(&fixture);
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("toolchain.tar");
        let payload = vec![7u8; 256 * 1024];
        std::fs::write(&path, &payload).unwrap();

        let worker: SocketAddr = "127.0.0.1:41000".parse().unwrap();
        let request = Request {
            target: Some(worker),
            method: Method::Post,
            path: "/api/v1/distserver/submit_toolchain/42".to_string(),
            authorization: Some("Bearer job-token".to_string()),
            body: Body::Stream {
                reader: Box::new(tokio::fs::File::open(&path).await.unwrap()),
                // The source is larger than the declared length (for example a
                // toolchain archive that grew after it was stat'ed): the
                // client must abort the upload instead of finishing it.
                len: (payload.len() - 4096) as u64,
            },
        };
        let error = expect_error(client.request(request).await);
        assert!(
            format!("{error:?}").contains("more than the declared"),
            "unexpected error: {error:?}"
        );
        assert!(
            fixture.request_log().is_empty(),
            "an aborted upload must never look like a complete request"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn reset_and_truncated_responses_are_errors() {
        let fixture = Fixture::start().await;
        let client = client(&fixture);

        // A response that is reset instead of finished must fail the request.
        // A reset can surface at any read stage, so only the observable
        // outcome is asserted: the RPC fails, the mutation is not retried, and
        // the gateway never sees anything beyond the one complete request.
        fixture.set_mode(MODE_RESET_AFTER_STATUS);
        let _error = expect_error(client.request(alloc_request()).await);
        assert_eq!(
            fixture.stream_count(),
            1,
            "a failed mutation must not be retried"
        );
        assert_eq!(
            fixture.request_log().len(),
            1,
            "only the complete request is visible to the gateway"
        );

        // A reset before any response bytes is the same failure.
        fixture.set_mode(MODE_RESET_IMMEDIATELY);
        assert!(client.request(alloc_request()).await.is_err());
        assert_eq!(
            fixture.stream_count(),
            2,
            "a failed mutation must not be retried"
        );
        assert_eq!(
            fixture.request_log().len(),
            1,
            "only the complete request is visible to the gateway"
        );

        // The connection itself survives a reset stream and keeps working.
        fixture.set_mode(MODE_OK);
        let response = client.request(status_request()).await.unwrap();
        assert_eq!(response.status, 200);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn http_error_status_is_preserved() {
        let fixture = Fixture::start().await;
        let client = client(&fixture);
        fixture.set_mode(MODE_HTTP_ERROR);
        let response = client.request(status_request()).await.unwrap();
        assert_eq!(response.status, 404);
        assert_eq!(response.body, b"{\"error\":\"unknown route\"}");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn descriptor_server_name_must_match_scheduler_host() {
        let fixture = Fixture::start().await;
        let mut descriptor = fixture.descriptor();
        descriptor.server_name = "somewhere.else".to_string();
        let client = QuicClient::from_descriptor(
            reqwest::Url::parse("https://localhost").unwrap(),
            "scheduler-token".to_string(),
            descriptor,
        );
        let error = expect_error(client.request(status_request()).await);
        assert!(
            format!("{error:?}").contains("does not match scheduler host"),
            "unexpected error: {error:?}"
        );
        assert_eq!(fixture.stream_count(), 0);
    }
}
