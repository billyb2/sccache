// billdfaster metadata-touch helper.
//
// This module is not part of upstream sccache. It is added by a focused
// patch that opts the S3 result-cache backend into last-use metadata
// tracking for the billdfaster distributed-build gateway.
//
// Contract (see billdfaster plan, step 5):
// - Before each actual native S3 read/write of a result object, send one
//   bounded authenticated JSON request
//   `{ "namespace": ..., "key": ..., "operation": "read"|"write" }`
//   (serialized body at most 2 KiB) to the configured touch endpoint and
//   await a durable acknowledgement.
// - The acknowledgement must carry a server-issued `expires_at_ms` (i64,
//   Unix epoch milliseconds) that is at most 60 seconds of server
//   wall-clock in the future and must still be in the future immediately
//   before the S3 transfer starts.
// - The native S3 operation must begin immediately after a successful
//   acknowledgement and is bounded to twenty minutes total including
//   retries. The budget is enforced both with a normal timer and against
//   absolute wall time at future poll boundaries so that host suspend
//   cannot pause the limit or revive an expired grant.
// - A metadata timeout/error is reported as a normal cache miss (for
//   reads) or a skipped cache write (for writes) through sccache's normal
//   error handling. It is never an untracked S3 access.
// - When the integration is disabled (no endpoint/token configured) this
//   module is never constructed and upstream behavior is unchanged.
//
// The helper reuses sccache's existing async HTTP/runtime stack (reqwest,
// already pulled in by the `s3` feature) and adds no daemon, runtime or
// alternate protocol.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::errors::{Result, anyhow};
use serde::{Deserialize, Serialize};

/// Patch revision of the billdfaster metadata-touch integration.
/// Bumped whenever this patch changes. Surfaced in `sccache --version`
/// and in `ServerInfo::version` as `+billdfaster.<rev>`.
pub const BF_PATCH_REVISION: &str = "3";

/// Total deadline for one metadata touch exchange, including Flycast cold
/// start, bounded retries and acknowledgement.
pub const TOUCH_DEADLINE: Duration = Duration::from_secs(300);

/// Maximum local grant lifetime. A small server/client clock skew is
/// accepted at admission, but never extends this local lifetime.
pub const MAX_ACK_EXPIRY: Duration = Duration::from_secs(60);
const MAX_CLOCK_SKEW_MS: i64 = 2_000;

/// Upper bound on the serialized JSON request body.
pub const MAX_BODY_BYTES: usize = 2048;

/// Upper bound on the acknowledged response body. The gateway replies
/// with a small JSON object; anything larger is malformed and rejected
/// before parsing.
pub const MAX_RESPONSE_BYTES: usize = 4096;

/// Total budget for one native cache operation (read or write) including
/// its preceding metadata acknowledgement and all S3 retries.
pub const NATIVE_OPERATION_BUDGET: Duration = Duration::from_secs(20 * 60);

/// Operation kinds admitted by the gateway. The wire case is lowercase,
/// as required by the gateway contract.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TouchOperation {
    Read,
    Write,
}

/// Request body for the metadata touch endpoint.
#[derive(Serialize)]
struct TouchRequest<'a> {
    namespace: &'a str,
    key: &'a str,
    operation: TouchOperation,
}

/// Durable acknowledgement returned by the gateway.
#[derive(Deserialize)]
struct TouchAck {
    expires_at_ms: i64,
}

/// Diagnostics for the metadata integration, surfaced in server stats.
/// Atomics are not `Copy`/`Clone`-derivable, so this struct is never
/// cloned or copied: it is shared through `TouchClient` and read via
/// `snapshot`.
#[derive(Default, Debug)]
pub struct TouchStats {
    /// Touch requests that were sent and acknowledged in time.
    touches_ok: AtomicU64,
    /// Touch requests that failed (timeout, transport, auth, bad ack,
    /// expired grant). Each failure bypasses or skips the associated
    /// native cache operation; it never results in untracked S3 access.
    touches_failed: AtomicU64,
}

impl TouchStats {
    fn record_ok(&self) {
        self.touches_ok.fetch_add(1, Ordering::Relaxed);
    }

    fn record_failed(&self) {
        self.touches_failed.fetch_add(1, Ordering::Relaxed);
    }

    /// `(acknowledged touches, failed touches)` snapshot.
    pub fn snapshot(&self) -> (u64, u64) {
        (
            self.touches_ok.load(Ordering::Relaxed),
            self.touches_failed.load(Ordering::Relaxed),
        )
    }
}

fn unix_millis() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        // A clock before the epoch cannot produce meaningful grants.
        .unwrap_or(i64::MIN)
}

/// Configuration for the metadata touch integration. The endpoint and
/// bearer token come from environment variables that are only
/// interpreted when the S3 result cache is configured; the namespace is
/// the same configured S3 key prefix passed in from the cache
/// configuration, never a separately guessed environment read.
#[derive(Clone, Debug)]
pub struct TouchConfig {
    endpoint: String,
    token: String,
    namespace: String,
}

impl TouchConfig {
    /// Build the opt-in configuration. Returns `None` when either the
    /// endpoint or the bearer token is not set; the integration is then
    /// fully disabled and upstream behavior is preserved.
    ///
    /// `namespace` must be the configured S3 `key_prefix` (as stored in
    /// `S3CacheConfig`, already trailing-slash-trimmed by upstream
    /// configuration parsing).
    pub fn from_parts(
        endpoint: Option<String>,
        token: Option<String>,
        namespace: String,
    ) -> Option<Self> {
        let endpoint = endpoint?;
        let token = token?;
        if endpoint.is_empty() || token.is_empty() {
            return None;
        }
        Some(Self {
            endpoint,
            token,
            namespace,
        })
    }

    fn serialize_request(&self, key: &str, operation: TouchOperation) -> Result<String> {
        let body = serde_json::to_string(&TouchRequest {
            namespace: &self.namespace,
            key,
            operation,
        })?;
        if body.len() > MAX_BODY_BYTES {
            return Err(anyhow!(
                "billdfaster touch request body {} bytes exceeds {}",
                body.len(),
                MAX_BODY_BYTES
            ));
        }
        Ok(body)
    }
}

/// A client for the billdfaster metadata touch endpoint.
pub struct TouchClient {
    config: TouchConfig,
    http: reqwest::Client,
    stats: TouchStats,
}

impl TouchClient {
    pub fn new(config: TouchConfig) -> Self {
        // No per-request client-level timeout: the total touch deadline
        // is enforced against absolute wall time around the whole retry
        // loop, so a per-attempt timeout cannot quietly reset the budget.
        let http = reqwest::Client::builder()
            .build()
            // A construction failure here is a programming/configuration
            // error; surface it loudly rather than silently disabling the
            // integration.
            .expect("failed to build billdfaster touch HTTP client");
        Self {
            config,
            http,
            stats: TouchStats::default(),
        }
    }

    /// `(acknowledged touches, failed touches)` snapshot.
    pub fn stats_snapshot(&self) -> (u64, u64) {
        self.stats.snapshot()
    }

    /// Perform one bounded, authenticated, idempotent touch exchange and
    /// return the server-issued expiry. Bounded retries with a total
    /// deadline of [`TOUCH_DEADLINE`] enforced against absolute wall
    /// time (not reset per attempt); the final attempt is not retried
    /// once the deadline has fully elapsed.
    pub async fn touch(&self, key: &str, operation: TouchOperation) -> Result<i64> {
        let body = self.config.serialize_request(key, operation)?;
        let url = &self.config.endpoint;
        // Absolute wall-clock deadline: host suspend cannot pause it.
        let deadline_millis = unix_millis()
            .checked_add(TOUCH_DEADLINE.as_millis() as i64)
            .ok_or_else(|| anyhow!("touch deadline overflow"))?;

        // Bounded retries: exponential backoff, capped, never past the
        // overall deadline. The touch is idempotent (the gateway applies
        // last_used_ms = max(old, server_now)) so repeats are safe.
        let mut delay = Duration::from_millis(250);
        loop {
            if unix_millis() >= deadline_millis {
                self.stats.record_failed();
                return Err(anyhow!(
                    "billdfaster touch total deadline {} ms exhausted",
                    TOUCH_DEADLINE.as_millis()
                ));
            }
            let request_started = unix_millis();
            let attempt = async {
                let mut response = self
                    .http
                    .post(url)
                    .header("Authorization", format!("Bearer {}", self.config.token))
                    .header("Content-Type", "application/json")
                    .body(body.clone())
                    .send()
                    .await?;
                let status = response.status();
                if !status.is_success() {
                    // Authentication failures and other errors are
                    // surfaced uniformly as metadata failures; the caller
                    // treats them as cache miss / skipped write.
                    return Err(anyhow!("touch endpoint returned status {}", status));
                }
                let mut full = Vec::new();
                while let Some(chunk) = response.chunk().await? {
                    if chunk.len() > MAX_RESPONSE_BYTES.saturating_sub(full.len()) {
                        return Err(anyhow!(
                            "touch response exceeds {} bytes",
                            MAX_RESPONSE_BYTES
                        ));
                    }
                    full.extend_from_slice(&chunk);
                }
                let ack: TouchAck = serde_json::from_slice(&full)?;
                bounded_grant_expiry(ack.expires_at_ms, unix_millis(), request_started)
            };

            let mut attempt = std::pin::pin!(attempt);
            let attempt = std::future::poll_fn(|cx| {
                if unix_millis() >= deadline_millis {
                    return std::task::Poll::Ready(Err(anyhow!(
                        "touch absolute deadline exhausted"
                    )));
                }
                Future::poll(attempt.as_mut(), cx)
            });
            match attempt.await {
                Ok(expires_at_ms) => {
                    self.stats.record_ok();
                    return Ok(expires_at_ms);
                }
                Err(err) => {
                    // Never retry past the total deadline: the check
                    // against absolute wall time gates every attempt.
                    if unix_millis() + delay.as_millis() as i64 >= deadline_millis {
                        self.stats.record_failed();
                        return Err(anyhow!("billdfaster touch failed: {err:#}"));
                    }
                    tokio::time::sleep(delay).await;
                    delay = (delay * 2).min(Duration::from_secs(5));
                }
            }
        }
    }

    /// Check, immediately before an S3 transfer starts, that a grant is
    /// still valid against absolute wall time. Returns the remaining
    /// validity. A suspended host cannot revive an expired grant because
    /// the check reads the real clock, not a paused timer.
    pub fn grant_remaining_millis(&self, expires_at_ms: i64) -> Result<i64> {
        let now = unix_millis();
        let remaining = expires_at_ms
            .checked_sub(now)
            .ok_or_else(|| anyhow!("invalid grant expiry"))?;
        if remaining <= 0 {
            return Err(anyhow!("billdfaster touch grant expired before S3 access"));
        }
        Ok(remaining)
    }

    /// The budget starts before metadata admission and covers the entire
    /// native transfer, including retries. Every poll checks wall time so
    /// laptop suspension cannot revive an expired operation.
    pub async fn access<T, F>(
        &self,
        key: &str,
        operation: TouchOperation,
        transfer: F,
    ) -> opendal::Result<T>
    where
        T: Send,
        F: Future<Output = opendal::Result<T>> + Send,
    {
        let deadline = unix_millis().saturating_add(NATIVE_OPERATION_BUDGET.as_millis() as i64);
        let admitted = async {
            let expiry = self.touch(key, operation).await.map_err(access_error)?;
            self.grant_remaining_millis(expiry).map_err(access_error)?;
            transfer.await
        };
        run_until(deadline, unix_millis, admitted).await
    }
}

fn bounded_grant_expiry(expiry: i64, now: i64, request_started: i64) -> Result<i64> {
    let remaining = expiry
        .checked_sub(now)
        .ok_or_else(|| anyhow!("invalid grant expiry"))?;
    let maximum = MAX_ACK_EXPIRY.as_millis() as i64;
    if now < request_started || remaining <= 0 || remaining > maximum + MAX_CLOCK_SKEW_MS {
        return Err(anyhow!(
            "touch acknowledgement expiry outside allowed lifetime"
        ));
    }
    // Anchor to request start, not response receipt: network delay must
    // not extend the server's sixty-second grant when its clock is ahead.
    let local_expiry = expiry.min(request_started.saturating_add(maximum));
    if local_expiry <= now {
        return Err(anyhow!("touch acknowledgement expired in transit"));
    }
    Ok(local_expiry)
}

fn access_error(error: impl std::fmt::Display) -> opendal::Error {
    opendal::Error::new(opendal::ErrorKind::Unexpected, error.to_string())
}

async fn run_until<T>(
    deadline: i64,
    now: impl Fn() -> i64,
    transfer: impl Future<Output = opendal::Result<T>>,
) -> opendal::Result<T> {
    let mut last_now = now();
    let remaining = deadline.saturating_sub(last_now).max(0) as u64;
    let mut transfer = std::pin::pin!(transfer);
    let guarded = std::future::poll_fn(|cx| {
        let current = now();
        if current < last_now || current >= deadline {
            return std::task::Poll::Ready(Err(access_error(
                "native S3 absolute deadline exhausted",
            )));
        }
        last_now = current;
        Future::poll(transfer.as_mut(), cx)
    });
    tokio::time::timeout(Duration::from_millis(remaining), guarded)
        .await
        .map_err(access_error)?
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn touch_config_from_parts_disabled_by_default() {
        // With neither variable provided the integration is off.
        assert!(TouchConfig::from_parts(None, None, "ns".into()).is_none());
        // Empty values are also disabled.
        assert!(
            TouchConfig::from_parts(Some(String::new()), Some("t".into()), "ns".into()).is_none()
        );
    }

    #[test]
    fn touch_config_namespace_from_cache_configuration() {
        let config = TouchConfig::from_parts(
            Some("http://unused.invalid".into()),
            Some("t".into()),
            "billdfaster/v1".into(),
        )
        .expect("config");
        let body = config
            .serialize_request("0123456789abcdef0123456789abcdef", TouchOperation::Read)
            .expect("serialization");
        assert!(body.contains("\"namespace\":\"billdfaster/v1\""), "{body}");
    }

    #[test]
    fn touch_request_serialization_bounds() {
        let config = TouchConfig::from_parts(
            Some("http://unused.invalid".into()),
            Some("t".into()),
            "billdfaster/v1/".into(),
        )
        .expect("config");
        let key = "0123456789abcdef0123456789abcdef";
        let body = config
            .serialize_request(key, TouchOperation::Read)
            .expect("serialization");
        assert!(body.len() <= MAX_BODY_BYTES);
        assert!(body.contains("\"operation\":\"read\""));
        assert!(body.contains("\"operation\""));
        assert!(!body.contains("write"));
        assert!(
            config
                .serialize_request(&"k".repeat(MAX_BODY_BYTES), TouchOperation::Read)
                .is_err()
        );
    }

    #[test]
    fn bounded_clock_skew_never_extends_local_grant() {
        assert_eq!(bounded_grant_expiry(70_008, 10_000, 9_900).unwrap(), 69_900);
        assert_eq!(bounded_grant_expiry(68_000, 10_000, 9_900).unwrap(), 68_000);
        assert!(bounded_grant_expiry(72_001, 10_000, 9_900).is_err());
        assert!(bounded_grant_expiry(10_000, 10_000, 9_900).is_err());
        assert!(bounded_grant_expiry(i64::MAX, -1, -1).is_err());
        assert!(bounded_grant_expiry(120_001, 60_000, 0).is_err());
        assert!(bounded_grant_expiry(70_000, 9_999, 10_000).is_err());
    }

    #[tokio::test]
    async fn expired_operation_cannot_resume_transfer() {
        use std::sync::atomic::{AtomicBool, AtomicI64};
        let now = AtomicI64::new(10_000);
        let transfer_completed = AtomicBool::new(false);
        let transfer = async {
            now.store(30_000, Ordering::SeqCst);
            tokio::task::yield_now().await;
            transfer_completed.store(true, Ordering::SeqCst);
            Ok(())
        };
        assert!(
            run_until(20_000, || now.load(Ordering::SeqCst), transfer)
                .await
                .is_err()
        );
        assert!(!transfer_completed.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn expired_operation_never_starts_transfer() {
        use std::sync::atomic::AtomicBool;
        let started = AtomicBool::new(false);
        let transfer = async {
            started.store(true, Ordering::SeqCst);
            Ok(())
        };
        assert!(run_until(20_000, || 20_000, transfer).await.is_err());
        assert!(!started.load(Ordering::SeqCst));
    }
}
