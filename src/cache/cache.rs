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

use super::cache_io::*;
#[cfg(feature = "azure")]
use crate::cache::azure::AzureBlobCache;
#[cfg(feature = "cos")]
use crate::cache::cos::COSCache;
use crate::cache::disk::DiskCache;
#[cfg(feature = "gcs")]
use crate::cache::gcs::GCSCache;
#[cfg(feature = "gha")]
use crate::cache::gha::GHACache;
#[cfg(feature = "memcached")]
use crate::cache::memcached::MemcachedCache;
use crate::cache::multilevel::{MultiLevelStats, MultiLevelStorage};
#[cfg(feature = "oss")]
use crate::cache::oss::OSSCache;
#[cfg(feature = "redis")]
use crate::cache::redis::RedisCache;
#[cfg(all(feature = "s3", feature = "dist-client"))]
#[cfg(all(feature = "s3", feature = "dist-client"))]
use crate::cache::relay::RelayOutcome;
use crate::cache::relay::RelayReader;
#[cfg(feature = "s3")]
use crate::cache::s3::S3Cache;
#[cfg(all(feature = "s3", feature = "dist-client"))]
use std::sync::atomic::{AtomicU64, Ordering};
#[cfg(any(
    feature = "azure",
    feature = "gcs",
    feature = "gha",
    feature = "memcached",
    feature = "redis",
    feature = "s3",
    feature = "webdav",
    feature = "oss",
    feature = "cos"
))]
use crate::cache::utils::normalize_key;
#[cfg(feature = "webdav")]
use crate::cache::webdav::WebdavCache;
use crate::compiler::PreprocessorCacheEntry;
use crate::config::Config;
use crate::config::{self, CacheType, PreprocessorCacheModeConfig};
use async_trait::async_trait;
use bytes::Bytes;
use serde::{Deserialize, Serialize};

use std::io;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use crate::errors::*;

/// Result of [`Storage::get_path`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GetPathResult {
    /// Cache hit: the entry lives at this filesystem path.
    Found(PathBuf),
    /// Cache miss: the key is not in the cache.
    Miss,
    /// This backend does not support direct file access; use `get`/`get_raw` instead.
    Unsupported,
}

/// Build the billdfaster metadata integration for one S3 namespace.
///
/// Both `SCCACHE_BILLDFASTER_TOUCH_ENDPOINT` and
/// `SCCACHE_BILLDFASTER_TOUCH_TOKEN` must be configured; otherwise the
/// integration is off and upstream behavior is unchanged. The namespace is
/// the cache's own configured S3 key prefix.
#[cfg(feature = "s3")]
pub fn billdfaster_touch_client(
    namespace: String,
) -> Option<crate::cache::billdfaster_touch::TouchClient> {
    let endpoint = std::env::var("SCCACHE_BILLDFASTER_TOUCH_ENDPOINT").ok();
    let token = std::env::var("SCCACHE_BILLDFASTER_TOUCH_TOKEN").ok();
    crate::cache::billdfaster_touch::TouchConfig::from_parts(endpoint, token, namespace)
        .map(crate::cache::billdfaster_touch::TouchClient::new)
}

/// An interface to cache storage.
#[async_trait]
pub trait Storage: Send + Sync {
    /// Get a cache entry by `key`.
    ///
    /// If an error occurs, this method should return a `Cache::Error`.
    /// If nothing fails but the entry is not found in the cache,
    /// it should return a `Cache::Miss`.
    /// If the entry is successfully found in the cache, it should
    /// return a `Cache::Hit`.
    async fn get(&self, key: &str) -> Result<Cache>;

    /// Get a parsed cache entry and, when supported, the same entry's raw bytes.
    ///
    /// Multi-level caches use the raw bytes to backfill faster levels. The
    /// default preserves compatibility with existing backends by retaining
    /// the historical second `get_raw()` call; raw-capable backends can
    /// override this to avoid reading a hit twice.
    async fn get_with_raw(&self, key: &str) -> Result<(Cache, Option<Bytes>)> {
        let cache = self.get(key).await?;
        let raw = if matches!(&cache, Cache::Hit(_)) {
            match self.get_raw(key).await {
                Ok(raw) => raw,
                Err(error) => {
                    debug!("Failed to get raw bytes for cache backfill: {}", error);
                    None
                }
            }
        } else {
            None
        };
        Ok((cache, raw))
    }

    /// Put `entry` in the cache under `key`.
    ///
    /// Returns a `Future` that will provide the result or error when the put is
    /// finished.
    async fn put(&self, key: &str, entry: CacheWrite) -> Result<Duration>;

    /// Get raw serialized cache entry bytes by `key` (for multi-level backfill).
    /// Returns `None` if the entry is not found, or if the implementation doesn't support raw access.
    /// This is used by multi-level caches to backfill faster levels.
    async fn get_raw(&self, _key: &str) -> Result<Option<Bytes>> {
        Ok(None)
    }

    /// Put raw serialized cache entry bytes under `key` (for multi-level backfill).
    /// Returns an error if the implementation doesn't support raw access.
    /// This is used by multi-level caches to backfill faster levels.
    async fn put_raw(&self, _key: &str, _data: Bytes) -> Result<Duration> {
        Err(anyhow!("put_raw not implemented for this storage backend"))
    }

    /// Check the cache capability.
    ///
    /// - `Ok(CacheMode::ReadOnly)` means cache can only be used to `get`
    ///   cache.
    /// - `Ok(CacheMode::ReadWrite)` means cache can do both `get` and `put`.
    /// - `Err(err)` means cache is not setup correctly or not match with
    ///   users input (for example, user try to use `ReadWrite` but cache
    ///   is `ReadOnly`).
    ///
    /// We will provide a default implementation which returns
    /// `Ok(CacheMode::ReadWrite)` for service that doesn't
    /// support check yet.
    async fn check(&self) -> Result<CacheMode> {
        Ok(CacheMode::ReadWrite)
    }

    /// Get the storage location.
    fn location(&self) -> String;

    /// Get the cache backend type name (e.g., "disk", "redis", "s3").
    /// Used for statistics and display purposes.
    fn cache_type_name(&self) -> &'static str {
        "unknown"
    }

    /// Get the current storage usage, if applicable.
    async fn current_size(&self) -> Result<Option<u64>>;

    /// Get the maximum storage size, if applicable.
    async fn max_size(&self) -> Result<Option<u64>>;

    /// Get multi-level cache statistics, if this is a multi-level storage.
    fn multilevel_stats(&self) -> Option<MultiLevelStats> {
        None
    }

    /// Return the config for preprocessor cache mode if applicable
    fn preprocessor_cache_mode_config(&self) -> PreprocessorCacheModeConfig {
        // Enable by default, only in local mode
        PreprocessorCacheModeConfig::default()
    }
    /// Return the base directories for path normalization if configured
    fn basedirs(&self) -> &[Vec<u8>] {
        &[]
    }
    /// Return the filesystem path of the cached entry for `key`.
    /// Default impl returns [`GetPathResult::Unsupported`].
    async fn get_path(&self, _key: &str) -> GetPathResult {
        GetPathResult::Unsupported
    }

    /// Return the preprocessor cache entry for a given preprocessor key,
    /// if it exists.
    /// Only applicable when using preprocessor cache mode.
    async fn get_preprocessor_cache_entry(
        &self,
        _key: &str,
    ) -> Result<Option<Box<dyn crate::lru_disk_cache::ReadSeek>>> {
        Ok(None)
    }
    /// Insert a preprocessor cache entry at the given preprocessor key,
    /// overwriting the entry if it exists.
    /// Only applicable when using preprocessor cache mode.
    async fn put_preprocessor_cache_entry(
        &self,
        _key: &str,
        _preprocessor_cache_entry: PreprocessorCacheEntry,
    ) -> Result<()> {
        Ok(())
    }

    /// billdfaster metadata-touch diagnostics snapshot:
    /// `(acknowledged touches, failed touches)`. Backends without the
    /// integration report `(0, 0)`.
    #[cfg(feature = "s3")]
    fn billdfaster_touch_stats(&self) -> (u64, u64) {
        (0, 0)
    }

    /// billdfaster relayed-read diagnostics:
    /// `(relayed hits, relayed failures)`. Misses are not failures. Backends
    /// without the integration report `(0, 0)`.
    fn billdfaster_relay_stats(&self) -> (u64, u64) {
        (0, 0)
    }
}

/// Wrapper for opendal::Operator that adds basedirs support
#[cfg(any(
    feature = "azure",
    feature = "gcs",
    feature = "gha",
    feature = "memcached",
    feature = "redis",
    feature = "s3",
    feature = "webdav",
    feature = "oss",
    feature = "cos"
))]
pub struct RemoteStorage {
    operator: opendal::Operator,
    basedirs: Vec<Vec<u8>>,
    rw_mode: CacheMode,
    skip_cache_check: bool,
    /// Optional billdfaster last-use metadata touch client. `None`
    /// (the default) preserves exact upstream behavior.
    #[cfg(feature = "s3")]
    touch_client: Option<crate::cache::billdfaster_touch::TouchClient>,
    /// Optional billdfaster relayed reader. When set (managed S3 cache with
    /// `[dist] quic = true`), result-object reads travel through the gateway
    /// over the shared dist QUIC connection instead of a direct S3 GET, and
    /// the gateway performs the last-use touch, so reads never touch S3
    /// directly and never send a second HTTP touch. Writes are unchanged.
    #[cfg(all(feature = "s3", feature = "dist-client"))]
    relay_reader: Option<RelayReader>,
    /// Relayed-read diagnostics: `(hits, failures)`. A relayed miss is not a
    /// failure. Both stay zero without a relayed reader.
    #[cfg(all(feature = "s3", feature = "dist-client"))]
    relay_stats: RelayStats,
}

#[cfg(any(
    feature = "azure",
    feature = "gcs",
    feature = "gha",
    feature = "memcached",
    feature = "redis",
    feature = "s3",
    feature = "webdav",
    feature = "oss",
    feature = "cos"
))]
impl RemoteStorage {
    pub fn new(operator: opendal::Operator, basedirs: Vec<Vec<u8>>, rw_mode: CacheMode) -> Self {
        Self {
            operator,
            basedirs,
            rw_mode,
            skip_cache_check: false,
            #[cfg(feature = "s3")]
            touch_client: None,
            #[cfg(all(feature = "s3", feature = "dist-client"))]
            relay_reader: None,
            #[cfg(all(feature = "s3", feature = "dist-client"))]
            relay_stats: RelayStats::default(),
        }
    }

    /// Opt this storage into the billdfaster last-use metadata touch
    /// integration. Only called from the S3 cache construction site when
    /// the opt-in environment variables are present.
    #[cfg(feature = "s3")]
    pub fn with_billdfaster_touch(
        mut self,
        touch_client: crate::cache::billdfaster_touch::TouchClient,
    ) -> Self {
        self.touch_client = Some(touch_client);
        self
    }

    /// Route result-object reads through the billdfaster gateway.
    ///
    /// The gateway performs the durable last-use touch for each read, so a
    /// relayed read must not also issue the direct HTTP touch. Writes keep
    /// their existing touch-on-write behavior.
    #[cfg(all(feature = "s3", feature = "dist-client"))]
    pub fn with_relay_reader(mut self, relay_reader: RelayReader) -> Self {
        self.relay_reader = Some(relay_reader);
        self
    }

    pub fn with_skip_cache_check(mut self, skip_cache_check: bool) -> Self {
        self.skip_cache_check = skip_cache_check;
        self
    }

    async fn read_with_touch(&self, key: &str) -> opendal::Result<opendal::Buffer> {
        #[cfg(all(feature = "s3", feature = "dist-client"))]
        if let Some(reader) = &self.relay_reader {
            return self.read_relayed(reader, key).await;
        }
        let key = normalize_key(key);
        #[cfg(feature = "s3")]
        if let Some(touch) = &self.touch_client {
            return touch
                .access(
                    &key,
                    crate::cache::billdfaster_touch::TouchOperation::Read,
                    self.operator.read(&key),
                )
                .await;
        }
        self.operator.read(&key).await
    }

    /// One relayed read. `key` is the raw, unsharded cache key: the gateway
    /// applies the canonical S3 shard path itself.
    #[cfg(all(feature = "s3", feature = "dist-client"))]
    async fn read_relayed(
        &self,
        reader: &RelayReader,
        key: &str,
    ) -> opendal::Result<opendal::Buffer> {
        match reader.read(key).await {
            Ok(RelayOutcome::Hit { data, .. }) => {
                self.relay_stats.record_hit();
                Ok(opendal::Buffer::from(data))
            }
            Ok(RelayOutcome::Miss) => Err(opendal::Error::new(
                opendal::ErrorKind::NotFound,
                "relayed cache miss",
            )),
            Err(error) => {
                self.relay_stats.record_failure();
                // Surface the failure exactly like any other unexpected
                // backend error. It is never turned into a direct S3 read.
                Err(opendal::Error::new(
                    opendal::ErrorKind::Unexpected,
                    error.to_string(),
                ))
            }
        }
    }
}

/// Implement storage for operator.
#[cfg(any(
    feature = "azure",
    feature = "gcs",
    feature = "gha",
    feature = "memcached",
    feature = "redis",
    feature = "s3",
    feature = "webdav",
    feature = "oss",
    feature = "cos"
))]
#[async_trait]
impl Storage for RemoteStorage {
    async fn get(&self, key: &str) -> Result<Cache> {
        Ok(self.get_with_raw(key).await?.0)
    }

    async fn get_with_raw(&self, key: &str) -> Result<(Cache, Option<Bytes>)> {
        match self.read_with_touch(key).await {
            Ok(res) => {
                // One owned buffer: the decode reads it in place and the
                // multilevel backfill takes the same bytes by refcount.
                let data = res.to_bytes();
                let hit = CacheRead::from(io::Cursor::new(data.clone()))?;
                Ok((Cache::Hit(hit), Some(data)))
            }
            Err(e) if e.kind() == opendal::ErrorKind::NotFound => Ok((Cache::Miss, None)),
            Err(e) => {
                #[cfg(all(feature = "s3", feature = "dist-client"))]
                if self.relay_reader.is_some() {
                    // A relayed read that failed is a cache failure, reported
                    // as such. It is never downgraded to a miss, so nothing
                    // downstream can retry it against S3 directly.
                    return Err(anyhow!("Failed to read raw bytes: {:?}", e));
                }
                warn!("Got unexpected error: {:?}", e);
                Ok((Cache::Miss, None))
            }
        }
    }

    async fn put(&self, key: &str, entry: CacheWrite) -> Result<Duration> {
        trace!("RemoteStorage::put({})", key);
        // Delegate to put_raw after serializing the entry
        let data = entry.finish()?;
        self.put_raw(key, data.into()).await
    }

    async fn check(&self) -> Result<CacheMode> {
        use opendal::ErrorKind;

        if self.skip_cache_check {
            debug!(
                "storage check skipped; using configured cache mode: {:?}",
                self.rw_mode
            );
            return Ok(self.rw_mode);
        }

        let path = ".sccache_check";

        // Read is required, return error directly if we can't read .
        match self.operator.read(path).await {
            Ok(_) => (),
            // Read not exist file with not found is ok.
            Err(err) if err.kind() == ErrorKind::NotFound => (),
            // Tricky Part.
            //
            // We tolerate rate limited here to make sccache keep running.
            // For the worse case, we will miss all the cache.
            //
            // In some super rare cases, user could configure storage in wrong
            // and hitting other services rate limit. There are few things we
            // can do, so we will print our the error here to make users know
            // about it.
            Err(err) if err.kind() == ErrorKind::RateLimited => {
                eprintln!("cache storage read check: {err:?}, but we decide to keep running");
            }
            Err(err) => bail!("cache storage failed to read: {:?}", err),
        }

        // No need to check write if we are in manually-set read-only mode
        if self.rw_mode == CacheMode::ReadOnly {
            let mode = CacheMode::ReadOnly;
            debug!("storage check result: {mode:?} (manually set)");
            return Ok(mode);
        }

        let can_write = match self.operator.write(path, "Hello, World!").await {
            Ok(_) => true,
            Err(err) if err.kind() == ErrorKind::AlreadyExists => true,
            // Tolerate all other write errors because we can do read at least.
            Err(err) => {
                eprintln!("storage write check failed: {err:?}");
                false
            }
        };

        let mode = if can_write {
            CacheMode::ReadWrite
        } else {
            CacheMode::ReadOnly
        };

        debug!("storage check result: {mode:?}");

        Ok(mode)
    }

    fn location(&self) -> String {
        let meta = self.operator.info();
        format!(
            "{}, name: {}, prefix: {}",
            meta.scheme(),
            meta.name(),
            meta.root()
        )
    }

    fn cache_type_name(&self) -> &'static str {
        // Use opendal's scheme as the cache type name
        // This returns "s3", "redis", "azure", "gcs", etc.
        self.operator.info().scheme()
    }

    async fn current_size(&self) -> Result<Option<u64>> {
        Ok(None)
    }

    async fn max_size(&self) -> Result<Option<u64>> {
        Ok(None)
    }

    fn basedirs(&self) -> &[Vec<u8>] {
        &self.basedirs
    }

    /// Get raw bytes from remote storage for multi-level backfill.
    ///
    /// Unlike `get()` which parses bytes into `CacheRead` (a `ZipArchive<Box<dyn ReadSeek>>`),
    /// this returns the raw bytes without parsing. `CacheRead` is a one-way transformation —
    /// there is no way to extract the original bytes back from the parsed ZIP archive.
    /// For backfill we need the raw bytes to write directly to another cache level.
    async fn get_raw(&self, key: &str) -> Result<Option<Bytes>> {
        trace!("opendal::Operator::get_raw({})", key);
        match self.read_with_touch(key).await {
            Ok(res) => {
                let data = res.to_bytes();
                trace!(
                    "opendal::Operator::get_raw({}): Found {} bytes",
                    key,
                    data.len()
                );
                Ok(Some(data))
            }
            Err(e) if e.kind() == opendal::ErrorKind::NotFound => {
                trace!("opendal::Operator::get_raw({}): NotFound", key);
                Ok(None)
            }
            Err(e) => {
                warn!("opendal::Operator::get_raw({}): Error: {:?}", key, e);
                // Return error instead of silently returning None
                Err(anyhow!("Failed to read raw bytes: {:?}", e))
            }
        }
    }

    /// Write raw bytes to remote storage for multi-level backfill.
    ///
    /// Unlike `put()` which takes a `CacheWrite` and serializes it, this writes
    /// pre-serialized bytes directly. Paired with `get_raw()` for efficient
    /// level-to-level data transfer without a deserialize/reserialize round-trip.
    async fn put_raw(&self, key: &str, data: Bytes) -> Result<Duration> {
        trace!("opendal::Operator::put_raw({}, {} bytes)", key, data.len());
        let start = std::time::Instant::now();

        if self.rw_mode == CacheMode::ReadOnly {
            bail!("storage is read-only");
        }

        let key = normalize_key(key);
        let write = self.operator.write(&key, data);
        #[cfg(feature = "s3")]
        match &self.touch_client {
            Some(touch) => {
                touch
                    .access(
                        &key,
                        crate::cache::billdfaster_touch::TouchOperation::Write,
                        write,
                    )
                    .await?;
            }
            None => {
                write.await?;
            }
        }
        #[cfg(not(feature = "s3"))]
        write.await?;

        Ok(start.elapsed())
    }

    #[cfg(feature = "s3")]
    fn billdfaster_touch_stats(&self) -> (u64, u64) {
        match &self.touch_client {
            Some(touch) => touch.stats_snapshot(),
            None => (0, 0),
        }
    }

    #[cfg(all(feature = "s3", feature = "dist-client"))]
    fn billdfaster_relay_stats(&self) -> (u64, u64) {
        self.relay_stats.snapshot()
    }
}

/// Relayed-read counters.
#[cfg(all(feature = "s3", feature = "dist-client"))]
#[derive(Default, Debug)]
pub struct RelayStats {
    hits: AtomicU64,
    failures: AtomicU64,
}

#[cfg(all(feature = "s3", feature = "dist-client"))]
impl RelayStats {
    fn record_hit(&self) {
        self.hits.fetch_add(1, Ordering::Relaxed);
    }

    fn record_failure(&self) {
        self.failures.fetch_add(1, Ordering::Relaxed);
    }

    fn snapshot(&self) -> (u64, u64) {
        (
            self.hits.load(Ordering::Relaxed),
            self.failures.load(Ordering::Relaxed),
        )
    }
}

/// Build a single cache storage from CacheType
/// Helper function used by storage_from_config for both single and multi-level caches
///
/// `relay_reader` is the billdfaster relayed result-cache reader. It is only
/// used by the managed S3 backend; every other backend ignores it.
#[cfg(any(
    feature = "azure",
    feature = "gcs",
    feature = "gha",
    feature = "memcached",
    feature = "redis",
    feature = "s3",
    feature = "webdav",
    feature = "oss",
    feature = "cos"
))]
pub fn build_single_cache(
    cache_type: &CacheType,
    basedirs: &[Vec<u8>],
    _pool: &tokio::runtime::Handle,
    skip_cache_check: bool,
    #[cfg_attr(
        not(all(feature = "s3", feature = "dist-client")),
        allow(unused_variables)
    )]
    relay_reader: Option<RelayReader>,
) -> Result<Arc<dyn Storage>> {
    match cache_type {
        #[cfg(feature = "azure")]
        CacheType::Azure(config::AzureCacheConfig {
            connection_string,
            container,
            key_prefix,
            storage_account,
            endpoint,
            rw_mode,
        }) => {
            debug!("Init azure cache with container {container}, key_prefix {key_prefix}");
            let operator = AzureBlobCache::build(
                connection_string.as_deref(),
                container,
                key_prefix,
                storage_account.as_deref(),
                endpoint.as_deref(),
            )
            .map_err(|err| anyhow!("create azure cache failed: {err:?}"))?;
            let storage = RemoteStorage::new(operator, basedirs.to_vec(), (*rw_mode).into())
                .with_skip_cache_check(skip_cache_check);
            Ok(Arc::new(storage))
        }
        #[cfg(feature = "gcs")]
        CacheType::GCS(config::GCSCacheConfig {
            bucket,
            key_prefix,
            cred_path,
            rw_mode,
            service_account,
            credential_url,
        }) => {
            debug!("Init gcs cache with bucket {bucket}, key_prefix {key_prefix}");

            let operator = GCSCache::build(
                bucket,
                key_prefix,
                cred_path.as_deref(),
                service_account.as_deref(),
                (*rw_mode).into(),
                credential_url.as_deref(),
            )
            .map_err(|err| anyhow!("create gcs cache failed: {err:?}"))?;
            let storage = RemoteStorage::new(operator, basedirs.to_vec(), (*rw_mode).into())
                .with_skip_cache_check(skip_cache_check);
            Ok(Arc::new(storage))
        }
        #[cfg(feature = "gha")]
        CacheType::GHA(config::GHACacheConfig {
            version, rw_mode, ..
        }) => {
            debug!("Init gha cache with version {version}");

            let operator = GHACache::build(version)
                .map_err(|err| anyhow!("create gha cache failed: {err:?}"))?;
            let storage = RemoteStorage::new(operator, basedirs.to_vec(), (*rw_mode).into())
                .with_skip_cache_check(skip_cache_check);
            Ok(Arc::new(storage))
        }
        #[cfg(feature = "memcached")]
        CacheType::Memcached(config::MemcachedCacheConfig {
            url,
            username,
            password,
            expiration,
            key_prefix,
            rw_mode,
        }) => {
            debug!("Init memcached cache with url {url}");

            let operator = MemcachedCache::build(
                url,
                username.as_deref(),
                password.as_deref(),
                key_prefix,
                *expiration,
            )
            .map_err(|err| anyhow!("create memcached cache failed: {err:?}"))?;
            let storage = RemoteStorage::new(operator, basedirs.to_vec(), (*rw_mode).into())
                .with_skip_cache_check(skip_cache_check);
            Ok(Arc::new(storage))
        }
        #[cfg(feature = "redis")]
        CacheType::Redis(config::RedisCacheConfig {
            endpoint,
            cluster_endpoints,
            username,
            password,
            db,
            url,
            ttl,
            key_prefix,
            rw_mode,
        }) => {
            let storage = match (endpoint, cluster_endpoints, url) {
                (Some(url), None, None) => {
                    debug!("Init redis single-node cache with url {url}");
                    RedisCache::build_single(
                        url,
                        username.as_deref(),
                        password.as_deref(),
                        *db,
                        key_prefix,
                        *ttl,
                    )
                }
                (None, Some(urls), None) => {
                    debug!("Init redis cluster cache with urls {urls}");
                    RedisCache::build_cluster(
                        urls,
                        username.as_deref(),
                        password.as_deref(),
                        *db,
                        key_prefix,
                        *ttl,
                    )
                }
                (None, None, Some(url)) => {
                    warn!("Init redis single-node cache from deprecated API with url {url}");
                    if username.is_some() || password.is_some() || *db != crate::config::DEFAULT_REDIS_DB {
                        bail!("`username`, `password` and `db` has no effect when `url` is set. Please use `endpoint` or `cluster_endpoints` for new API accessing");
                    }

                    RedisCache::build_from_url(url, key_prefix, *ttl)
                }
                _ => bail!("Only one of `endpoint`, `cluster_endpoints`, `url` must be set"),
            }
            .map_err(|err| anyhow!("create redis cache failed: {err:?}"))?;
            let storage = RemoteStorage::new(storage, basedirs.to_vec(), (*rw_mode).into())
                .with_skip_cache_check(skip_cache_check);
            Ok(Arc::new(storage))
        }
        #[cfg(feature = "s3")]
        CacheType::S3(c) => {
            debug!(
                "Init s3 cache with bucket {}, endpoint {:?}",
                c.bucket, c.endpoint
            );
            let s3_cache_builder =
                S3Cache::new(c.bucket.clone(), c.key_prefix.clone(), c.no_credentials);
            let operator = s3_cache_builder
                .with_region(c.region.clone())
                .with_endpoint(c.endpoint.clone())
                .with_use_ssl(c.use_ssl)
                .with_server_side_encryption(c.server_side_encryption)
                .with_server_side_encryption_aws_kms(c.server_side_encryption_aws_kms)
                .with_server_side_encryption_kms_key_id(c.server_side_encryption_kms_key_id.clone())
                .with_enable_virtual_host_style(c.enable_virtual_host_style)
                .build()
                .map_err(|err| anyhow!("create s3 cache failed: {err:?}"))?;

            // billdfaster opt-in: when the touch endpoint/token are
            // configured, S3 result-object accesses are tracked with
            // last-use metadata. Otherwise upstream behavior is exactly
            // preserved. The namespace is this cache's own configured
            // key prefix (already trailing-slash-trimmed by upstream
            // configuration parsing), never a separately guessed
            // environment read.
            let storage_builder = match billdfaster_touch_client(c.key_prefix.clone()) {
                Some(touch_config) => {
                    debug!("billdfaster metadata touch integration enabled");
                    RemoteStorage::new(operator, basedirs.to_vec(), c.rw_mode.into())
                        .with_skip_cache_check(skip_cache_check)
                        .with_billdfaster_touch(touch_config)
                }
                None => RemoteStorage::new(operator, basedirs.to_vec(), c.rw_mode.into())
                    .with_skip_cache_check(skip_cache_check),
            };
            // A relayed reader replaces the direct read path: the gateway
            // performs the metadata grant and the origin GET itself, so reads
            // are never both relayed and touched again over HTTP.
            #[cfg(feature = "dist-client")]
            let storage_builder = match relay_reader {
                Some(reader) => {
                    debug!(
                        "billdfaster relayed result-cache reads enabled for namespace {}",
                        c.key_prefix
                    );
                    storage_builder.with_relay_reader(reader)
                }
                None => storage_builder,
            };
            Ok(Arc::new(storage_builder))
        }
        #[cfg(feature = "webdav")]
        CacheType::Webdav(c) => {
            debug!("Init webdav cache with endpoint {}", c.endpoint);

            let operator = WebdavCache::build(
                &c.endpoint,
                &c.key_prefix,
                c.username.as_deref(),
                c.password.as_deref(),
                c.token.as_deref(),
            )
            .map_err(|err| anyhow!("create webdav cache failed: {err:?}"))?;

            let storage = RemoteStorage::new(operator, basedirs.to_vec(), c.rw_mode.into())
                .with_skip_cache_check(skip_cache_check);
            Ok(Arc::new(storage))
        }
        #[cfg(feature = "oss")]
        CacheType::OSS(c) => {
            debug!(
                "Init oss cache with bucket {}, endpoint {:?}",
                c.bucket, c.endpoint
            );

            let operator = OSSCache::build(
                &c.bucket,
                &c.key_prefix,
                c.endpoint.as_deref(),
                c.no_credentials,
            )
            .map_err(|err| anyhow!("create oss cache failed: {err:?}"))?;

            let storage = RemoteStorage::new(operator, basedirs.to_vec(), c.rw_mode.into())
                .with_skip_cache_check(skip_cache_check);
            Ok(Arc::new(storage))
        }
        #[cfg(feature = "cos")]
        CacheType::COS(c) => {
            debug!(
                "Init cos cache with bucket {}, endpoint {:?}",
                c.bucket, c.endpoint
            );

            let operator = COSCache::build(&c.bucket, &c.key_prefix, c.endpoint.as_deref())
                .map_err(|err| anyhow!("create cos cache failed: {err:?}"))?;

            let storage = RemoteStorage::new(operator, basedirs.to_vec(), c.rw_mode.into())
                .with_skip_cache_check(skip_cache_check);
            Ok(Arc::new(storage))
        }
        #[allow(unreachable_patterns)]
        _ => {
            bail!("Cache type not supported with current feature configuration")
        }
    }
}

/// Get a suitable `Storage` implementation from configuration.
/// Supports both single-cache (backward compatible) and multi-level cache configurations.
///
/// `relay_reader` selects billdfaster relayed result-cache reads for the
/// managed S3 backend; it is forwarded to every configured level so a
/// multilevel chain whose S3 level is reached reads through the gateway too.
pub fn storage_from_config(
    config: &Config,
    pool: &tokio::runtime::Handle,
    #[cfg_attr(
        not(all(feature = "s3", feature = "dist-client")),
        allow(unused_variables)
    )]
    relay_reader: Option<RelayReader>,
) -> Result<Arc<dyn Storage>> {
    // Check for multi-level cache configuration
    if let Some(multilevel) = MultiLevelStorage::from_config(config, pool, relay_reader.clone())? {
        return Ok(Arc::new(multilevel));
    }

    // Single cache or fallback to disk (backward compatible path)
    #[cfg(any(
        feature = "azure",
        feature = "gcs",
        feature = "gha",
        feature = "memcached",
        feature = "redis",
        feature = "s3",
        feature = "webdav",
        feature = "oss",
        feature = "cos"
    ))]
    if let Some(cache_type) = &config.cache {
        debug!("Configuring single cache from CacheType");
        return build_single_cache(
            cache_type,
            &config.basedirs,
            pool,
            config.skip_cache_check,
            relay_reader,
        );
    }

    // No remote cache configured - use disk cache only
    let (dir, size) = (&config.fallback_cache.dir, config.fallback_cache.size);
    let preprocessor_cache_mode_config = config.fallback_cache.preprocessor_cache_mode;
    let rw_mode = config.fallback_cache.rw_mode.into();
    debug!("Init disk cache with dir {:?}, size {}", dir, size);
    Ok(Arc::new(DiskCache::new(
        dir,
        size,
        pool,
        preprocessor_cache_mode_config,
        rw_mode,
        config.basedirs.clone(),
    )))
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::config::CacheModeConfig;
    use fs_err as fs;

    #[test]
    fn test_read_write_mode_local() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .worker_threads(1)
            .build()
            .unwrap();

        // Use disk cache.
        let mut config = Config {
            cache: None,
            ..Default::default()
        };

        let tempdir = tempfile::Builder::new()
            .prefix("sccache_test_rust_cargo")
            .tempdir()
            .context("Failed to create tempdir")
            .unwrap();
        let cache_dir = tempdir.path().join("cache");
        fs::create_dir(&cache_dir).unwrap();

        config.fallback_cache.dir = cache_dir;

        // Test Read Write
        config.fallback_cache.rw_mode = CacheModeConfig::ReadWrite;

        {
            let cache = storage_from_config(&config, runtime.handle(), None).unwrap();

            runtime.block_on(async move {
                cache.put("test1", CacheWrite::default()).await.unwrap();
                cache
                    .put_preprocessor_cache_entry("test1", PreprocessorCacheEntry::default())
                    .await
                    .unwrap();
            });
        }

        // Test Read-only
        config.fallback_cache.rw_mode = CacheModeConfig::ReadOnly;

        {
            let cache = storage_from_config(&config, runtime.handle(), None).unwrap();

            runtime.block_on(async move {
                assert_eq!(
                    cache
                        .put("test1", CacheWrite::default())
                        .await
                        .unwrap_err()
                        .to_string(),
                    "Cannot write to a read-only cache"
                );
                assert_eq!(
                    cache
                        .put_preprocessor_cache_entry("test1", PreprocessorCacheEntry::default())
                        .await
                        .unwrap_err()
                        .to_string(),
                    "Cannot write to a read-only cache"
                );
            });
        }
    }

    #[test]
    #[cfg(feature = "s3")]
    fn test_operator_storage_s3_with_basedirs() {
        // Create S3 operator (doesn't need real credentials for this test)
        let operator = crate::cache::s3::S3Cache::new(
            "test-bucket".to_string(),
            "test-prefix".to_string(),
            true, // no_credentials = true
        )
        .with_region(Some("us-east-1".to_string()))
        .build()
        .expect("Failed to create S3 cache operator");

        let basedirs = vec![b"/home/user/project".to_vec(), b"/opt/build".to_vec()];

        // Wrap with OperatorStorage
        let storage = RemoteStorage::new(operator, basedirs.clone(), CacheMode::ReadWrite);

        // Verify basedirs are stored and retrieved correctly
        assert_eq!(storage.basedirs(), basedirs.as_slice());
        assert_eq!(storage.basedirs().len(), 2);
        assert_eq!(storage.basedirs()[0], b"/home/user/project".to_vec());
        assert_eq!(storage.basedirs()[1], b"/opt/build".to_vec());
    }

    #[test]
    #[cfg(feature = "s3")]
    fn test_skip_remote_cache_check_uses_configured_mode() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        for (configured_mode, expected_mode) in [
            (CacheModeConfig::ReadOnly, CacheMode::ReadOnly),
            (CacheModeConfig::ReadWrite, CacheMode::ReadWrite),
        ] {
            let cache_config = config::S3CacheConfig {
                bucket: "test-bucket".to_owned(),
                region: Some("us-east-1".to_owned()),
                key_prefix: String::new(),
                no_credentials: true,
                endpoint: Some("http://127.0.0.1:1".to_owned()),
                use_ssl: Some(false),
                server_side_encryption: None,
                server_side_encryption_aws_kms: None,
                server_side_encryption_kms_key_id: None,
                enable_virtual_host_style: None,
                rw_mode: configured_mode,
            };
            let single_cache_config = Config {
                cache: Some(CacheType::S3(cache_config.clone())),
                skip_cache_check: true,
                ..Default::default()
            };

            let storage = storage_from_config(&single_cache_config, runtime.handle(), None).unwrap();
            assert_eq!(runtime.block_on(storage.check()).unwrap(), expected_mode);

            let multilevel_config = Config {
                cache_configs: config::CacheConfigs {
                    s3: Some(cache_config),
                    multilevel: Some(config::MultiLevelConfig {
                        chain: vec!["s3".to_owned()],
                        write_error_policy: config::WriteErrorPolicy::default(),
                    }),
                    ..Default::default()
                },
                skip_cache_check: true,
                ..Default::default()
            };

            let storage = storage_from_config(&multilevel_config, runtime.handle(), None).unwrap();
            assert_eq!(runtime.block_on(storage.check()).unwrap(), expected_mode);
        }
    }

    #[test]
    #[cfg(feature = "redis")]
    fn test_operator_storage_redis_with_basedirs() {
        // Create Redis operator
        let operator = crate::cache::redis::RedisCache::build_single(
            "redis://localhost:6379",
            None,
            None,
            0,
            "test-prefix",
            0,
        )
        .expect("Failed to create Redis cache operator");

        let basedirs = vec![b"/workspace".to_vec()];

        // Wrap with OperatorStorage
        let storage = RemoteStorage::new(operator, basedirs.clone(), CacheMode::ReadWrite);

        // Verify basedirs work
        assert_eq!(storage.basedirs(), basedirs.as_slice());
        assert_eq!(storage.basedirs().len(), 1);
    }

    /// Storage-level relayed-read semantics: the consumer sees a hit, a miss
    /// or an error, but the S3 operator is never read and no second touch is
    /// issued.
    #[cfg(all(feature = "s3", feature = "dist-client"))]
    mod relayed_reads {
        use super::*;
        use crate::cache::relay::{CacheReadTransport, RelayOutcome, RelayReader};
        use crate::dist::quic::{Request, Response};
        use parking_lot::Mutex;
        use std::sync::Arc;
        use std::time::Duration;

        struct Fake {
            outcome: Mutex<Option<std::result::Result<RelayOutcome, String>>>,
            requests: Mutex<Vec<Request>>,
        }

        #[async_trait]
        impl CacheReadTransport for Fake {
            async fn request(&self, request: Request) -> Result<Response> {
                self.requests.lock().push(request);
                match self.outcome.lock().take().expect("one read per test") {
                    Ok(RelayOutcome::Hit { data, object_len }) => Ok(Response {
                        status: 200,
                        body: {
                            let mut body = object_len.to_be_bytes().to_vec();
                            body.extend_from_slice(&data);
                            body
                        },
                    }),
                    Ok(RelayOutcome::Miss) => Ok(Response {
                        status: 404,
                        body: Vec::new(),
                    }),
                    Err(message) => Err(anyhow!(message)),
                }
            }
        }

        fn storage(outcome: std::result::Result<RelayOutcome, String>) -> (Arc<Fake>, RemoteStorage) {
            let fake = Arc::new(Fake {
                outcome: Mutex::new(Some(outcome)),
                requests: Mutex::new(Vec::new()),
            });
            let reader = RelayReader::new(
                Arc::clone(&fake) as Arc<dyn CacheReadTransport>,
                "billdfaster/v1".to_owned(),
                "metadata-token".to_owned(),
            );
            let operator = crate::cache::s3::S3Cache::new(
                "bucket".to_owned(),
                "billdfaster/v1".to_owned(),
                true,
            )
            .with_region(Some("us-east-1".to_owned()))
            .with_endpoint(Some("http://127.0.0.1:9".to_owned()))
            .with_use_ssl(Some(false))
            .build()
            .expect("operator");
            let storage =
                RemoteStorage::new(operator, vec![], CacheMode::ReadWrite).with_relay_reader(reader);
            (fake, storage)
        }

        fn entry_bytes() -> Vec<u8> {
            CacheWrite::default().finish().expect("cache entry").into()
        }

        #[test]
        fn hit_comes_from_the_gateway_with_the_raw_key() {
            let data = entry_bytes();
            let (fake, storage) = storage(Ok(RelayOutcome::Hit {
                data: data.clone().into(),
                object_len: data.len() as u64,
            }));
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            let (cache, raw) = runtime
                .block_on(async { storage.get_with_raw("0123456789abcdef0123456789abcdef").await })
                .expect("relayed hit");
            assert!(matches!(cache, Cache::Hit(_)));
            assert_eq!(raw.expect("raw bytes").as_ref(), data.as_slice());
            assert_eq!(storage.billdfaster_relay_stats(), (1, 0));

            let requests = fake.requests.lock();
            assert_eq!(requests[0].path, "/v1/cache/read");
            let body = match &requests[0].body {
                crate::dist::quic::Body::Bytes(body) => String::from_utf8(body.clone()).unwrap(),
                _ => panic!("expected an in-memory body"),
            };
            assert_eq!(
                body,
                r#"{"namespace":"billdfaster/v1","key":"0123456789abcdef0123456789abcdef"}"#
            );
        }

        #[test]
        fn relayed_level_failure_stops_the_chain_instead_of_falling_through() {
            // A later level would happily answer a miss, so the relayed
            // level's failure must not be downgraded to one.
            let (_fake, relayed) = storage(Err("gateway unavailable".to_owned()));
            struct AlwaysHit;
            #[async_trait]
            impl Storage for AlwaysHit {
                async fn get(&self, _key: &str) -> Result<Cache> {
                    Ok(Cache::Hit(CacheRead::from(io::Cursor::new(entry_bytes()))?))
                }
                async fn put(&self, _key: &str, _entry: CacheWrite) -> Result<Duration> {
                    Ok(Duration::default())
                }
                async fn check(&self) -> Result<CacheMode> {
                    Ok(CacheMode::ReadWrite)
                }
                fn location(&self) -> String {
                    "later-level".to_owned()
                }
                async fn current_size(&self) -> Result<Option<u64>> {
                    Ok(None)
                }
                async fn max_size(&self) -> Result<Option<u64>> {
                    Ok(None)
                }
            }
            let later = Arc::new(AlwaysHit);
            let mut chain = crate::cache::multilevel::MultiLevelStorage::new(vec![
                Arc::new(relayed) as Arc<dyn Storage>,
                later,
            ]);
            chain.set_relayed_levels(vec![true, false]);
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            assert!(runtime
                .block_on(chain.get("0123456789abcdef0123456789abcdef"))
                .is_err());
        }

        #[test]
        fn missing_object_is_a_miss() {
            let (_fake, storage) = storage(Ok(RelayOutcome::Miss));
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            let cache = runtime
                .block_on(storage.get("0123456789abcdef0123456789abcdef"))
                .expect("miss");
            assert!(matches!(cache, Cache::Miss));
            assert_eq!(storage.billdfaster_relay_stats(), (0, 0));
        }

        #[test]
        fn relayed_failure_is_a_cache_error_not_a_miss() {
            let (_fake, storage) = storage(Err("gateway unavailable".to_owned()));
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            // A failure must not look like a miss: nothing may retry it
            // elsewhere, and no direct S3 read is attempted.
            assert!(runtime
                .block_on(storage.get("0123456789abcdef0123456789abcdef"))
                .is_err());
            assert_eq!(storage.billdfaster_relay_stats(), (0, 1));
        }
    }

    #[test]
    #[cfg(feature = "redis")]
    fn test_operator_storage_redis_with_read_only() {
        // Create Redis operator

        use crate::test::utils::Waiter;
        let operator = crate::cache::redis::RedisCache::build_single(
            "redis://localhost:6379",
            None,
            None,
            0,
            "test-prefix",
            0,
        )
        .expect("Failed to create Redis cache operator");

        // Wrap with OperatorStorage
        let storage = RemoteStorage::new(operator, vec![], CacheMode::ReadOnly);

        // Verify put fails
        let result = storage.put("test", CacheWrite::default()).wait();
        match result {
            Ok(_) => panic!("expected error, got success {result:?}"),
            Err(err) => assert_eq!(err.to_string(), "storage is read-only"),
        }
    }
}
