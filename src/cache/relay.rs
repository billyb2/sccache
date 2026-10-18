// billdfaster relayed result-cache reads.
//
// This module is not part of upstream sccache. Managed S3 result caches that
// are served by a billdfaster gateway with `[dist] quic = true` read their
// result objects through that gateway instead of opening a direct S3 GET:
// the persistent QUIC transport already used for scheduler and worker RPCs
// also carries `POST /v1/cache/read`, so a cached compile downloads exactly
// once from Tigris, through the origin that already holds the object.
//
// Wire contract (client half; the gateway mirrors it):
// - `target = None`, `POST /v1/cache/read`, `client_token` = scheduler token,
//   `authorization = Bearer <metadata token>` (the same
//   `SCCACHE_BILLDFASTER_TOUCH_TOKEN` value the metadata touch client uses).
// - JSON body is exactly `{"namespace": <S3 key prefix>, "key": <raw key>}`,
//   at most [`MAX_REQUEST_BYTES`]. `key` is the *raw* cache key; the gateway
//   applies the cache's own S3 shard path, so sharding is never duplicated.
// - This is a mutation at the origin (it durably touches last-use metadata),
//   so it is never attempted as 0-RTT early data and never retried.
// - `200` carries an 8-byte big-endian unsigned compressed object length,
//   then exactly that many original cache-entry bytes, then FIN.
// - `404` is an ordinary cache miss. Any other status, or any truncated,
//   overlong or malformed `200`, is a cache failure. A failure is never
//   retried against S3 directly.
// - The whole exchange is bounded by [`CACHE_READ_DEADLINE`] (the gateway's
//   own deadline is at most the same 60 s), and an artifact is bounded by the
//   worker artifact limit plus the length prefix.
//
// The reader deliberately holds no transport of its own: the distributed
// client's own [`crate::dist::quic::QuicClient`] is injected explicitly when
// the cache storage is built, so result-cache reads and compiler RPCs share
// one endpoint, TLS session store and connection. There is no global and no
// second endpoint. A deployment that selected this read path never falls back
// to direct S3 reads: a missing or failed transport is a cache failure, and
// startup refuses to build a relayed cache without a transport.

#[cfg(all(feature = "s3", feature = "dist-client"))]
use std::sync::Arc;
#[cfg(all(feature = "s3", feature = "dist-client"))]
use std::time::{Duration, Instant};

#[cfg(all(feature = "s3", feature = "dist-client"))]
use crate::errors::Context as _;
#[cfg(all(feature = "s3", feature = "dist-client"))]
use crate::errors::{Result, anyhow, bail};

/// Absolute request/response body bound from the wire contract. The body is
/// exactly one namespace plus one raw cache key.
#[cfg(all(feature = "s3", feature = "dist-client"))]
pub const MAX_REQUEST_BYTES: usize = 2048;
/// Length of the big-endian compressed-object length prefix.
#[cfg(all(feature = "s3", feature = "dist-client"))]
pub const LENGTH_PREFIX_BYTES: usize = 8;
/// The gateway's cache-read deadline, and therefore this client's total
/// deadline for one relayed read.
#[cfg(all(feature = "s3", feature = "dist-client"))]
pub const CACHE_READ_DEADLINE: Duration = Duration::from_secs(60);
/// Largest cache entry the gateway serves (the existing worker artifact
/// bound). The response adds [`LENGTH_PREFIX_BYTES`] to it.
#[cfg(all(feature = "s3", feature = "dist-client"))]
pub const MAX_ARTIFACT_BYTES: u64 = 8 * 1024 * 1024 * 1024;

/// Request body. Field order is fixed so the encoding is byte-for-byte
/// predictable, and unknown fields are rejected by the gateway.
#[cfg(all(feature = "s3", feature = "dist-client"))]
#[derive(serde::Serialize)]
struct CacheReadRequest<'a> {
    namespace: &'a str,
    key: &'a str,
}

/// Encode the relayed-read request body, enforcing the wire bound.
#[cfg(all(feature = "s3", feature = "dist-client"))]
pub fn encode_request(namespace: &str, key: &str) -> Result<Vec<u8>> {
    let body = serde_json::to_vec(&CacheReadRequest { namespace, key })
        .context("failed to encode the relayed cache-read request")?;
    if body.len() > MAX_REQUEST_BYTES {
        bail!(
            "relayed cache-read request body of {} bytes exceeds the {} byte bound",
            body.len(),
            MAX_REQUEST_BYTES
        );
    }
    Ok(body)
}

/// A relayed read that reached an outcome other than a hit or a miss.
#[cfg(all(feature = "s3", feature = "dist-client"))]
#[derive(Debug)]
pub enum RelayReadError {
    /// The gateway answered with a diagnostic body; reported verbatim.
    Status { status: u16, message: String },
    /// The exchange itself failed (transport, deadline, malformed `200`).
    Transport(anyhow::Error),
}

#[cfg(all(feature = "s3", feature = "dist-client"))]
impl std::fmt::Display for RelayReadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RelayReadError::Status { status, message } => {
                write!(f, "relayed cache read returned status {status}: {message}")
            }
            RelayReadError::Transport(error) => write!(f, "relayed cache read failed: {error:#}"),
        }
    }
}

#[cfg(all(feature = "s3", feature = "dist-client"))]
impl std::error::Error for RelayReadError {}

/// Outcome of one relayed read.
#[cfg(all(feature = "s3", feature = "dist-client"))]
#[derive(Debug)]
pub enum RelayOutcome {
    Hit {
        /// The original cache-entry bytes, with the length prefix removed.
        data: bytes::Bytes,
        /// Compressed object length announced by the gateway.
        object_len: u64,
    },
    Miss,
}

/// Transport relayed reads are performed over. The production
/// implementation is the dist client's shared [`crate::dist::quic::QuicClient`]
/// (one endpoint, session store and connection per client), so result-cache
/// reads and compiler RPCs share transport state rather than each opening
/// their own.
#[cfg(all(feature = "s3", feature = "dist-client"))]
#[async_trait::async_trait]
pub trait CacheReadTransport: Send + Sync {
    async fn request(
        &self,
        request: crate::dist::quic::Request,
    ) -> Result<crate::dist::quic::Response>;
}

#[cfg(all(feature = "s3", feature = "dist-client"))]
#[async_trait::async_trait]
impl CacheReadTransport for crate::dist::quic::QuicClient {
    async fn request(
        &self,
        request: crate::dist::quic::Request,
    ) -> Result<crate::dist::quic::Response> {
        crate::dist::quic::QuicClient::request(self, request).await
    }
}

/// Type used by the cache builders for the injected reader.
///
/// Builds with `s3` but without `dist-client` (native-only profiles) cannot
/// relay: there is no QUIC transport to carry the request. They use the same
/// signature with an uninhabited placeholder so the cache layer keeps one
/// shape in every feature combination and never gains a second code path.
#[cfg(not(all(feature = "s3", feature = "dist-client")))]
#[derive(Clone)]
pub enum RelayReader {}

#[cfg(not(all(feature = "s3", feature = "dist-client")))]
impl RelayReader {
    /// Never available: the reader is only constructed by the managed S3
    /// cache path, which requires both the `s3` and `dist-client` features.
    pub fn absent() -> Option<Self> {
        None
    }
}

/// Client for relayed result-cache reads, bound to one cache namespace.
#[cfg(all(feature = "s3", feature = "dist-client"))]
#[derive(Clone)]
pub struct RelayReader {
    transport: Arc<dyn CacheReadTransport>,
    namespace: String,
    token: String,
    /// Total deadline for one relayed read.
    deadline: Duration,
}

#[cfg(all(feature = "s3", feature = "dist-client"))]
impl std::fmt::Debug for RelayReader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RelayReader")
            .field("namespace", &self.namespace)
            .field("deadline", &self.deadline)
            .finish_non_exhaustive()
    }
}

#[cfg(all(feature = "s3", feature = "dist-client"))]
impl RelayReader {
    /// Bind a reader to a shared QUIC transport for `namespace` (the
    /// configured S3 key prefix) with `token` (the metadata bearer).
    ///
    /// The transport is the dist client's own
    /// [`crate::dist::quic::QuicClient`], injected at construction. Cache
    /// reads therefore reuse the connection and session state of compiler
    /// RPCs and never open a second endpoint.
    pub fn new(
        transport: Arc<dyn CacheReadTransport>,
        namespace: String,
        token: String,
    ) -> Self {
        Self {
            transport,
            namespace,
            token,
            deadline: CACHE_READ_DEADLINE,
        }
    }

    /// Test hook: shorten the total deadline so expiry is reachable quickly.
    #[cfg(test)]
    pub fn with_deadline(mut self, deadline: Duration) -> Self {
        self.deadline = deadline;
        self
    }

    /// Read one raw (unsharded) cache key through the gateway.
    ///
    /// A [`RelayOutcome::Miss`] is a normal cache miss. Every other failure
    /// is a [`RelayReadError`] that the caller reports as a cache failure;
    /// nothing here ever falls back to a direct S3 read.
    pub async fn read(&self, key: &str) -> std::result::Result<RelayOutcome, RelayReadError> {
        let body = encode_request(&self.namespace, key).map_err(RelayReadError::Transport)?;
        let request = crate::dist::quic::Request {
            target: None,
            // The gateway performs a durable metadata touch, so this is a
            // mutation: no 0-RTT, no retries.
            method: crate::dist::quic::Method::Post,
            path: CACHE_READ_PATH.to_owned(),
            authorization: Some(format!("Bearer {}", self.token)),
            body: crate::dist::quic::Body::Bytes(body),
        };
        let started = Instant::now();
        let response = tokio::time::timeout(self.deadline, self.transport.request(request))
            .await
            .map_err(|_| {
                RelayReadError::Transport(anyhow!(
                    "relayed cache read timed out after {:?}",
                    self.deadline
                ))
            })?
            .map_err(RelayReadError::Transport)?;
        // The whole exchange, including the artifact transfer, must fit the
        // gateway deadline; a stream that only finished late is not a hit.
        if started.elapsed() > self.deadline {
            return Err(RelayReadError::Transport(anyhow!(
                "relayed cache read returned after its {:?} deadline",
                self.deadline
            )));
        }
        decode_response(response)
    }
}

/// Gateway route for relayed result-cache reads.
#[cfg(all(feature = "s3", feature = "dist-client"))]
pub const CACHE_READ_PATH: &str = "/v1/cache/read";

/// Decode one gateway response per the wire contract.
#[cfg(all(feature = "s3", feature = "dist-client"))]
pub fn decode_response(
    response: crate::dist::quic::Response,
) -> std::result::Result<RelayOutcome, RelayReadError> {
    match response.status {
        200 => {
            let body = response.body;
            if body.len() < LENGTH_PREFIX_BYTES {
                return Err(RelayReadError::Transport(anyhow!(
                    "relayed cache read returned {} bytes, shorter than its {} byte length prefix",
                    body.len(),
                    LENGTH_PREFIX_BYTES
                )));
            }
            let mut prefix = [0u8; LENGTH_PREFIX_BYTES];
            prefix.copy_from_slice(&body[..LENGTH_PREFIX_BYTES]);
            let object_len = u64::from_be_bytes(prefix);
            if object_len > MAX_ARTIFACT_BYTES {
                return Err(RelayReadError::Transport(anyhow!(
                    "relayed cache read announced {object_len} bytes, above the {MAX_ARTIFACT_BYTES} byte artifact cap"
                )));
            }
            let delivered = body.len() - LENGTH_PREFIX_BYTES;
            if delivered as u64 != object_len {
                return Err(RelayReadError::Transport(anyhow!(
                    "relayed cache read announced {object_len} bytes but delivered {delivered}"
                )));
            }
            // Retain the received allocation; slicing off the prefix does not
            // allocate or copy the artifact.
            let data = bytes::Bytes::from(body).slice(LENGTH_PREFIX_BYTES..);
            Ok(RelayOutcome::Hit { data, object_len })
        }
        404 => Ok(RelayOutcome::Miss),
        status => Err(RelayReadError::Status {
            status,
            message: String::from_utf8_lossy(&response.body).into_owned(),
        }),
    }
}

#[cfg(all(test, feature = "s3", feature = "dist-client"))]
mod test {
    use super::*;
    use crate::dist::quic::{Body, Method, Request, Response};

    struct Recording {
        response: parking_lot::Mutex<Option<Response>>,
        requests: parking_lot::Mutex<Vec<Request>>,
    }

    impl Recording {
        fn new(response: Response) -> Self {
            Self {
                response: parking_lot::Mutex::new(Some(response)),
                requests: parking_lot::Mutex::new(Vec::new()),
            }
        }
    }

    #[async_trait::async_trait]
    impl CacheReadTransport for Recording {
        async fn request(&self, request: Request) -> Result<Response> {
            self.requests.lock().push(request);
            Ok(self
                .response
                .lock()
                .take()
                .expect("one request per recording"))
        }
    }

    fn hit(object: &[u8]) -> Response {
        let mut body = (object.len() as u64).to_be_bytes().to_vec();
        body.extend_from_slice(object);
        Response { status: 200, body }
    }

    fn reader(response: Response) -> (Arc<Recording>, RelayReader) {
        let recording = Arc::new(Recording::new(response));
        let reader = RelayReader::new(
            Arc::clone(&recording) as Arc<dyn CacheReadTransport>,
            "billdfaster/v1".into(),
            "metadata-token".into(),
        );
        (recording, reader)
    }

    #[tokio::test]
    async fn hit_is_sent_as_an_allowlisted_post_with_the_raw_key() {
        let (recording, client) = reader(hit(b"archive-bytes"));
        match client.read("0123456789abcdef0123456789abcdef").await {
            Ok(RelayOutcome::Hit { data, object_len }) => {
                assert_eq!(data.as_ref(), b"archive-bytes");
                assert_eq!(object_len, 13);
            }
            other => panic!("expected hit, got {}", describe(&other)),
        }
        let requests = recording.requests.lock();
        let request = &requests[0];
        assert_eq!(request.method, Method::Post);
        assert_eq!(request.target, None);
        assert_eq!(request.path, "/v1/cache/read");
        assert_eq!(request.authorization.as_deref(), Some("Bearer metadata-token"));
        match &request.body {
            Body::Bytes(body) => assert_eq!(
                std::str::from_utf8(body).unwrap(),
                r#"{"namespace":"billdfaster/v1","key":"0123456789abcdef0123456789abcdef"}"#
            ),
            _ => panic!("expected an in-memory body"),
        }
        assert!(!request.is_read_only_for_test(), "no 0-RTT for a mutation");
    }

    fn describe<T>(outcome: &std::result::Result<RelayOutcome, T>) -> String {
        match outcome {
            Ok(RelayOutcome::Hit { .. }) => "hit".to_owned(),
            Ok(RelayOutcome::Miss) => "miss".to_owned(),
            Err(_) => "error".to_owned(),
        }
    }

    #[tokio::test]
    async fn missing_object_is_a_plain_miss() {
        let (_, client) = reader(Response { status: 404, body: Vec::new() });
        assert!(matches!(
            client.read("0123456789abcdef0123456789abcdef").await,
            Ok(RelayOutcome::Miss)
        ));
    }

    #[tokio::test]
    async fn rejection_and_unavailable_statuses_are_errors_never_misses() {
        for status in [400u16, 401, 403, 503] {
            let (_, client) = reader(Response { status, body: b"nope".to_vec() });
            match client.read("0123456789abcdef0123456789abcdef").await {
                Err(RelayReadError::Status { status: seen, message }) => {
                    assert_eq!(seen, status);
                    assert_eq!(message, "nope");
                }
                _ => panic!("status {status} must be an error"),
            }
        }
    }

    #[tokio::test]
    async fn truncated_overlong_and_malformed_sizes_are_errors() {
        // Short prefix.
        let (_, client) = reader(Response { status: 200, body: vec![0; 7] });
        assert!(client.read("k".repeat(32).as_str()).await.is_err());

        // Announced longer than delivered (reset or FIN mid-artifact).
        let mut short = 16u64.to_be_bytes().to_vec();
        short.extend_from_slice(b"partial");
        let (_, client) = reader(Response { status: 200, body: short });
        assert!(client.read("k".repeat(32).as_str()).await.is_err());

        // Announced shorter than delivered.
        let mut long = 2u64.to_be_bytes().to_vec();
        long.extend_from_slice(b"too-many-bytes");
        let (_, client) = reader(Response { status: 200, body: long });
        assert!(client.read("k".repeat(32).as_str()).await.is_err());

        // Above the artifact cap.
        let mut huge = (MAX_ARTIFACT_BYTES + 1).to_be_bytes().to_vec();
        huge.push(0);
        let (_, client) = reader(Response { status: 200, body: huge });
        assert!(client.read("k".repeat(32).as_str()).await.is_err());
    }

    #[tokio::test]
    async fn empty_object_is_still_a_valid_size_prefix() {
        let (_, client) = reader(hit(b""));
        match client.read("k".repeat(32).as_str()).await {
            Ok(RelayOutcome::Hit { data, object_len }) => {
                assert!(data.is_empty());
                assert_eq!(object_len, 0);
            }
            _ => panic!("a zero-length announced object is well formed"),
        }
    }

    #[tokio::test]
    async fn oversized_request_is_rejected_before_the_transport() {
        let (recording, _) = reader(hit(b"x"));
        let client = RelayReader::new(
            Arc::clone(&recording) as Arc<dyn CacheReadTransport>,
            "n".repeat(MAX_REQUEST_BYTES),
            "t".into(),
        );
        assert!(client.read("k").await.is_err());
        assert!(recording.requests.lock().is_empty());
    }

    #[tokio::test]
    async fn deadline_bounds_the_exchange() {
        struct Silent;
        #[async_trait::async_trait]
        impl CacheReadTransport for Silent {
            async fn request(&self, _: Request) -> Result<Response> {
                futures::future::pending().await
            }
        }
        let client = RelayReader::new(
            Arc::new(Silent) as Arc<dyn CacheReadTransport>,
            "ns".into(),
            "t".into(),
        )
        .with_deadline(Duration::from_millis(20));
        let started = Instant::now();
        assert!(client.read("k").await.is_err());
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn request_encoding_is_bounded() {
        assert!(encode_request("ns", "0123456789abcdef0123456789abcdef").is_ok());
        let too_long = encode_request("ns", &"k".repeat(MAX_REQUEST_BYTES));
        assert!(too_long.is_err());
    }
}
