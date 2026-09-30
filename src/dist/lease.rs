// billdfaster build-lease client.
//
// This module is not part of upstream sccache. It is added by a focused patch
// that keeps the gateway's workers for as long as a *real* local build process
// is alive, instead of inferring demand from compiler traffic.
//
// The daemon holds at most one renewable lease per local build owner (see
// [`crate::build_owner`]). The lease capability is a random 256-bit id minted
// here and never logged; the wire request carries nothing else. Every mutation
// goes over the selected distributed transport ([`crate::dist::http::Client`]
// QUIC or the pinned HTTP client), is bounded by a short deadline of its own,
// and is never retried or replayed: an ambiguous outcome stays ambiguous and
// the gateway's TTL covers it.
//
// Retention contract:
// - one lease per owner, acquired on the first compiler request before any
//   remote allocation,
// - renewed every [`LeaseTimings::renew`] while the owner lives,
// - the owner's exit is observed at [`LeaseTimings::liveness`] ticks,
//   independently of in-flight renewals,
// - a release is attempted once, best effort, after the owner exits,
// - a definitive "unknown lease" renewal retires the lease locally instead of
//   recreating it,
// - the registry is bounded, so a pathological caller cannot grow it.

use crate::build_owner::{self, BuildOwner};
use crate::errors::*;
use async_trait::async_trait;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, Notify};
use tokio::task::{JoinHandle, JoinSet};

/// Production cadence: liveness ticks.
pub const LIVENESS_INTERVAL: Duration = Duration::from_secs(2);
/// Production cadence: renewals.
pub const RENEW_INTERVAL: Duration = Duration::from_secs(20);
/// Deadline for one lease mutation, independent of the compile RPC timeout.
pub const RPC_DEADLINE: Duration = Duration::from_secs(5);
/// Largest TTL a gateway response may report.
pub const MAX_LEASE_TTL_SECONDS: u64 = 600;
/// Upper bound on tracked owners per daemon.
pub const MAX_TRACKED_OWNERS: usize = 32;
/// How often a concurrent first request re-checks a pending acquire.
const ACQUIRE_WAIT_STEP: Duration = Duration::from_millis(25);
/// Extra time a request waits for an acquisition to settle beyond the RPC
/// deadline the acquisition itself is bounded by.
const ADMISSION_GRACE: Duration = Duration::from_secs(1);

/// The operation of one build-lease mutation.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum BuildLeaseOperation {
    Acquire,
    Renew,
    Release,
}

impl BuildLeaseOperation {
    /// Wire spelling used in the request body.
    pub fn as_str(self) -> &'static str {
        match self {
            BuildLeaseOperation::Acquire => "acquire",
            BuildLeaseOperation::Renew => "renew",
            BuildLeaseOperation::Release => "release",
        }
    }
}

/// Request body: exactly these two fields, at most 1024 bytes.
#[derive(Serialize, Debug)]
pub struct BuildLeaseRequest<'a> {
    pub operation: &'a str,
    pub lease_id: &'a str,
}

/// Success body of an acquire or renew.
#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct BuildLeaseHeld {
    pub lease_id: String,
    pub ttl_seconds: u64,
}

/// Success body of a release.
#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct BuildLeaseReleased {
    pub released: bool,
}

/// A gateway answer to one lease mutation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BuildLeaseOutcome {
    /// Acquire or renew succeeded.
    Held { lease_id: String, ttl_seconds: u64 },
    /// Release succeeded; `released` reports whether a live lease was removed.
    Released { released: bool },
}

/// A failed lease mutation.
///
/// `status` is the gateway's HTTP status when it answered; `None` means the
/// outcome is unknown (transport failure, timeout, or an undecodable body).
#[derive(Debug)]
pub struct BuildLeaseFailure {
    pub status: Option<u16>,
    pub source: anyhow::Error,
}

impl BuildLeaseFailure {
    /// The outcome is unknown: never retry this mutation.
    pub fn ambiguous(source: impl Into<anyhow::Error>) -> Self {
        Self {
            status: None,
            source: source.into(),
        }
    }

    /// The gateway answered with a status that is not a success.
    pub fn gateway(status: u16, source: impl Into<anyhow::Error>) -> Self {
        Self {
            status: Some(status),
            source: source.into(),
        }
    }

    /// Whether the gateway refused an acquire because this exact capability
    /// is already live.
    ///
    /// The keeper does not adopt such a lease: a 409 does not prove remaining
    /// TTL or a successful admission, so any acquire failure - duplicate
    /// included - leaves the owner unleased with no renewals.
    pub fn is_duplicate(&self) -> bool {
        self.status == Some(409)
    }

    /// Whether the gateway definitively does not know this lease any more.
    pub fn is_unknown_lease(&self) -> bool {
        self.status == Some(404)
    }

    /// Whether the outcome of the mutation is unknown.
    pub fn is_ambiguous(&self) -> bool {
        self.status.is_none()
    }
}

impl std::fmt::Display for BuildLeaseFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.status {
            Some(status) => write!(f, "gateway status {status}: {}", self.source),
            None => write!(f, "{}", self.source),
        }
    }
}

impl std::error::Error for BuildLeaseFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.source.as_ref())
    }
}

/// Mint a fresh 256-bit capability as 64 lowercase hex characters.
pub fn new_lease_id() -> String {
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut id = String::with_capacity(64);
    for byte in bytes {
        id.push(HEX[(byte >> 4) as usize] as char);
        id.push(HEX[(byte & 0x0f) as usize] as char);
    }
    id
}

/// Whether `id` is exactly the 64 lowercase hex characters the gateway
/// accepts.
pub fn is_valid_lease_id(id: &str) -> bool {
    id.len() == 64
        && id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Replace anything shaped like a lease capability with a placeholder.
///
/// Gateway error bodies are quoted in logs and error messages; a capability
/// must never appear there.
fn redact_lease_ids(text: &str) -> String {
    let mut redacted = String::with_capacity(text.len());
    let bytes = text.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        let end = index + 64;
        if end <= bytes.len()
            && bytes[index..end]
                .iter()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
        {
            redacted.push_str("<lease-id>");
            index = end;
            continue;
        }
        let character = text[index..].chars().next().expect("char boundary");
        redacted.push(character);
        index += character.len_utf8();
    }
    redacted
}

/// Decode one lease mutation response.
///
/// Both transports share this so status handling is identical, and it is
/// deliberately explicit: only `200` is a success, the lease id must be
/// echoed verbatim, the TTL must be sane, and every body is strict JSON.
pub fn decode_build_lease_response(
    operation: BuildLeaseOperation,
    expected_lease_id: &str,
    status: u16,
    body: &[u8],
) -> std::result::Result<BuildLeaseOutcome, BuildLeaseFailure> {
    if status != 200 {
        return Err(BuildLeaseFailure::gateway(
            status,
            anyhow!(
                "build lease {} rejected: {}",
                operation.as_str(),
                redact_lease_ids(&String::from_utf8_lossy(body))
            ),
        ));
    }
    let malformed =
        |error: anyhow::Error| BuildLeaseFailure::ambiguous(error.context("build lease response"));
    match operation {
        BuildLeaseOperation::Acquire | BuildLeaseOperation::Renew => {
            let held: BuildLeaseHeld =
                serde_json::from_slice(body).map_err(|error| malformed(anyhow!(error)))?;
            if held.lease_id != expected_lease_id {
                return Err(malformed(anyhow!(
                    "the response echoed a different lease id"
                )));
            }
            if held.ttl_seconds == 0 || held.ttl_seconds > MAX_LEASE_TTL_SECONDS {
                return Err(malformed(anyhow!(
                    "the response reported an out of range ttl"
                )));
            }
            Ok(BuildLeaseOutcome::Held {
                lease_id: held.lease_id,
                ttl_seconds: held.ttl_seconds,
            })
        }
        BuildLeaseOperation::Release => {
            let released: BuildLeaseReleased =
                serde_json::from_slice(body).map_err(|error| malformed(anyhow!(error)))?;
            Ok(BuildLeaseOutcome::Released {
                released: released.released,
            })
        }
    }
}

/// Sends one lease mutation over the selected distributed transport.
#[async_trait]
pub trait BuildLeaseSender: Send + Sync {
    /// Send `operation` for `lease_id`. Implementations must not retry,
    /// replay, or fall back to another transport.
    async fn send(
        &self,
        operation: BuildLeaseOperation,
        lease_id: &str,
    ) -> std::result::Result<BuildLeaseOutcome, BuildLeaseFailure>;
}

/// Whether an owner still names exactly one live process.
pub trait OwnerReader: Send + Sync {
    fn is_live(&self, owner: &BuildOwner) -> bool;
}

/// The kernel-backed reader used in production.
pub struct KernelOwnerReader;

impl OwnerReader for KernelOwnerReader {
    fn is_live(&self, owner: &BuildOwner) -> bool {
        build_owner::validate_build_owner(owner)
    }
}

/// Cadence and bounds of one keeper.
#[derive(Clone, Copy, Debug)]
pub struct LeaseTimings {
    /// How often owner liveness is checked.
    pub liveness: Duration,
    /// How often a held lease is renewed.
    pub renew: Duration,
    /// Deadline for one lease mutation.
    pub rpc: Duration,
}

impl Default for LeaseTimings {
    fn default() -> Self {
        Self {
            liveness: LIVENESS_INTERVAL,
            renew: RENEW_INTERVAL,
            rpc: RPC_DEADLINE,
        }
    }
}

/// Lifecycle of one tracked owner.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    /// A first request is acquiring; other requests for the same owner wait.
    Acquiring,
    /// A lease is held and renewed.
    Held,
    /// The owner exited; a bounded release is in flight.
    Releasing,
    /// The lease is definitively gone or expired; no more mutations.
    Lost,
    /// No lease was ever obtained for this owner; no retries.
    Unleased,
}

struct Entry {
    lease_id: String,
    phase: Phase,
    /// When the gateway lease provably expires (last success + TTL).
    held_until: Option<Instant>,
    /// When the next renewal is due.
    next_renew: Option<Instant>,
    /// Whether a renewal or release is in flight for this entry.
    inflight: bool,
    /// The bounded acquisition this entry owns, if one is still running.
    /// The keeper owns it, not the request that asked for it.
    acquire: Option<JoinHandle<()>>,
    /// Bumped whenever an entry is replaced, so stale operations are ignored.
    generation: u64,
}

impl Entry {
    fn new(lease_id: String) -> Self {
        Self {
            lease_id,
            phase: Phase::Acquiring,
            held_until: None,
            next_renew: None,
            inflight: false,
            acquire: None,
            generation: 0,
        }
    }
}

#[derive(Default)]
struct Registry {
    entries: HashMap<BuildOwner, Entry>,
    order: VecDeque<BuildOwner>,
    next_generation: u64,
}

impl Registry {
    fn is_full(&self) -> bool {
        self.entries.len() >= MAX_TRACKED_OWNERS
    }

    /// Track `owner` without evicting anything. Returns false when the owner
    /// is already tracked or the registry is full.
    fn insert(&mut self, owner: BuildOwner) -> bool {
        if self.entries.contains_key(&owner) || self.is_full() {
            return false;
        }
        self.next_generation = self.next_generation.wrapping_add(1);
        let mut entry = Entry::new(new_lease_id());
        entry.generation = self.next_generation;
        self.entries.insert(owner, entry);
        self.order.push_back(owner);
        true
    }

    /// Owners whose lease ended definitively, oldest first. A tombstone may
    /// only be pruned once its owner is gone: while the process lives it is
    /// what keeps a failed or lost acquire from being replayed.
    fn terminal_tombstones(&self) -> Vec<BuildOwner> {
        self.order
            .iter()
            .copied()
            .filter(|key| {
                matches!(
                    self.entries.get(key).map(|entry| entry.phase),
                    Some(Phase::Lost | Phase::Unleased)
                )
            })
            .collect()
    }

    /// Prune one terminal tombstone. Returns false when the entry is gone or
    /// is no longer terminal.
    fn prune_terminal(&mut self, owner: &BuildOwner) -> bool {
        match self.entries.get(owner).map(|entry| entry.phase) {
            Some(Phase::Lost | Phase::Unleased) => {
                self.remove(owner);
                true
            }
            _ => false,
        }
    }

    fn remove(&mut self, owner: &BuildOwner) {
        if let Some(entry) = self.entries.remove(owner)
            && let Some(acquire) = entry.acquire
        {
            acquire.abort();
        }
        if let Some(index) = self.order.iter().position(|key| key == owner) {
            self.order.remove(index);
        }
    }

    /// Lease ids that may exist at the gateway, oldest first. Empties the
    /// registry: the caller owns the returned capabilities.
    fn take_live_lease_ids(&mut self) -> Vec<String> {
        let ids = self
            .order
            .iter()
            .filter_map(|key| {
                let entry = self.entries.get(key)?;
                match entry.phase {
                    Phase::Acquiring | Phase::Held | Phase::Releasing => {
                        Some(entry.lease_id.clone())
                    }
                    Phase::Lost | Phase::Unleased => None,
                }
            })
            .collect();
        for entry in self.entries.values_mut() {
            if let Some(acquire) = entry.acquire.take() {
                acquire.abort();
            }
        }
        self.entries.clear();
        self.order.clear();
        ids
    }

    fn held_count(&self) -> usize {
        self.entries
            .values()
            .filter(|entry| entry.phase == Phase::Held)
            .count()
    }
}

/// Outcome of one supervisor-spawned mutation.
enum OpOutcome {
    Renew {
        owner: BuildOwner,
        generation: u64,
        /// When the mutation was sent: the gateway's TTL starts before the
        /// answer arrives, so expiry is derived from this instant.
        started: Instant,
        result: std::result::Result<BuildLeaseOutcome, BuildLeaseFailure>,
    },
    Release {
        owner: BuildOwner,
        generation: u64,
        result: std::result::Result<BuildLeaseOutcome, BuildLeaseFailure>,
    },
}

/// When a granted lease expires: the reported TTL measured from the instant
/// the mutation was *sent*, which is the earliest the gateway could have
/// started counting. Treating the response instant as the start would let this
/// daemon believe in retention up to one RPC deadline past the real expiry.
fn granted_until(started: Instant, ttl_seconds: u64) -> Instant {
    started + Duration::from_secs(ttl_seconds)
}

/// When the next renewal is due, never at or after the conservative expiry.
fn next_renew_at(now: Instant, interval: Duration, expires_at: Instant) -> Instant {
    let candidate = now + interval;
    if candidate < expires_at {
        candidate
    } else {
        expires_at
    }
}

struct Shared {
    sender: Arc<dyn BuildLeaseSender>,
    reader: Arc<dyn OwnerReader>,
    timings: LeaseTimings,
    state: Mutex<Registry>,
    closed: AtomicBool,
    notify: Notify,
    /// The daemon runtime, so acquisitions are spawned on it rather than on
    /// whichever task asked for one.
    runtime: tokio::runtime::Handle,
}

/// Per-daemon registry of renewable build leases, one per live build owner.
pub struct BuildLeaseKeeper {
    shared: Arc<Shared>,
    supervisor: JoinHandle<()>,
}

impl BuildLeaseKeeper {
    /// Create a keeper on the daemon's runtime.
    pub fn new(sender: Arc<dyn BuildLeaseSender>, runtime: &tokio::runtime::Handle) -> Arc<Self> {
        Self::with_parts(
            sender,
            Arc::new(KernelOwnerReader),
            LeaseTimings::default(),
            runtime,
        )
    }

    /// Create a keeper with explicit parts.
    pub(crate) fn with_parts(
        sender: Arc<dyn BuildLeaseSender>,
        reader: Arc<dyn OwnerReader>,
        timings: LeaseTimings,
        runtime: &tokio::runtime::Handle,
    ) -> Arc<Self> {
        let shared = Arc::new(Shared {
            sender,
            reader,
            timings,
            state: Mutex::new(Registry::default()),
            closed: AtomicBool::new(false),
            notify: Notify::new(),
            runtime: runtime.clone(),
        });
        let supervisor = runtime.spawn(supervise(Arc::clone(&shared)));
        Arc::new(Self { shared, supervisor })
    }

    /// Record one compiler request from `owner`.
    ///
    /// The first request for an owner starts a bounded, keeper-owned
    /// acquisition and then waits (bounded) for it to settle, so this compile
    /// cannot allocate before the lease exists. Cancelling this request never
    /// cancels the acquisition and never leaves the owner stranded: the
    /// keeper-owned task always moves the entry out of `Acquiring`. Later
    /// requests are cheap no-ops. Every failure is local: a compile never
    /// fails because a lease could not be obtained.
    pub async fn ensure(&self, owner: &BuildOwner) {
        if self.shared.closed.load(Ordering::SeqCst) {
            return;
        }
        if !self.shared.reader.is_live(owner) {
            debug!(
                "build lease: ignoring owner that is not a live same-uid process (pid {})",
                owner.pid
            );
            return;
        }
        match self.track(owner).await {
            Tracked::Inserted | Tracked::AlreadyTracked => self.await_admission(owner).await,
            Tracked::Closed => {}
            Tracked::Full => warn!(
                "build lease: {} owners are already tracked, not tracking pid {}",
                MAX_TRACKED_OWNERS, owner.pid
            ),
        }
    }

    /// Track `owner`, pruning at most one tombstone whose owner has exited.
    ///
    /// A tombstone belonging to a *live* process is never pruned: its first
    /// acquisition may still exist at the gateway, and tracking it again would
    /// mint a second capability for one build.
    async fn track(&self, owner: &BuildOwner) -> Tracked {
        let mut state = self.shared.state.lock().await;
        if self.shared.closed.load(Ordering::SeqCst) {
            return Tracked::Closed;
        }
        if state.entries.contains_key(owner) {
            return Tracked::AlreadyTracked;
        }
        if state.insert(*owner) {
            self.begin_acquire(&mut state, *owner);
            return Tracked::Inserted;
        }
        let candidates = state.terminal_tombstones();
        drop(state);
        // Liveness is checked without the registry lock: it reads the kernel.
        let Some(dead) = candidates
            .into_iter()
            .find(|key| !self.shared.reader.is_live(key))
        else {
            return Tracked::Full;
        };
        let mut state = self.shared.state.lock().await;
        if self.shared.closed.load(Ordering::SeqCst) {
            return Tracked::Closed;
        }
        if state.entries.contains_key(owner) {
            return Tracked::AlreadyTracked;
        }
        if !state.prune_terminal(&dead) {
            return Tracked::Full;
        }
        if state.insert(*owner) {
            self.begin_acquire(&mut state, *owner);
            Tracked::Inserted
        } else {
            Tracked::Full
        }
    }

    /// Wait, bounded, until this owner's acquisition has settled.
    ///
    /// The wait is what keeps a first compile from allocating before its lease
    /// exists; it never owns the acquisition, so cancellation here only stops
    /// this request.
    async fn await_admission(&self, owner: &BuildOwner) {
        let deadline = Instant::now() + self.shared.timings.rpc + ADMISSION_GRACE;
        loop {
            let phase = self
                .shared
                .state
                .lock()
                .await
                .entries
                .get(owner)
                .map(|entry| entry.phase);
            if phase != Some(Phase::Acquiring) {
                return;
            }
            if Instant::now() >= deadline {
                return;
            }
            let _ = tokio::time::timeout(ACQUIRE_WAIT_STEP, self.shared.notify.notified()).await;
        }
    }

    /// Number of owners currently holding a live lease.
    pub async fn active_leases(&self) -> usize {
        self.shared.state.lock().await.held_count()
    }

    /// An idle daemon must remain alive while it owns build retention.
    /// Polling cannot await the registry lock; contention conservatively keeps
    /// the daemon alive until the next bounded inactivity check.
    pub(crate) fn retains_builds(&self) -> bool {
        match self.shared.state.try_lock() {
            Ok(state) => state.entries.values().any(|entry| {
                matches!(
                    entry.phase,
                    Phase::Acquiring | Phase::Held | Phase::Releasing
                )
            }),
            Err(_) => true,
        }
    }

    /// Stop renewing and best-effort release every lease within `budget`.
    ///
    /// Called on the daemon's shutdown path before the runtime is torn down.
    /// Failures are ignored: the gateway's TTL is the upper bound on any lease
    /// this cannot release.
    pub async fn shutdown(&self, budget: Duration) {
        self.shared.closed.store(true, Ordering::SeqCst);
        self.shared.notify.notify_waiters();
        self.supervisor.abort();
        let lease_ids = self.shared.state.lock().await.take_live_lease_ids();
        if lease_ids.is_empty() {
            return;
        }
        let deadline = Instant::now() + budget;
        let releases = lease_ids.into_iter().map(|lease_id| {
            let shared = Arc::clone(&self.shared);
            async move {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    return;
                }
                match tokio::time::timeout(
                    remaining,
                    shared.sender.send(BuildLeaseOperation::Release, &lease_id),
                )
                .await
                {
                    Ok(Ok(_)) => {}
                    Ok(Err(failure)) => {
                        debug!("build lease release failed during shutdown: {failure}")
                    }
                    Err(_) => debug!("build lease release timed out during shutdown"),
                }
            }
        });
        futures::future::join_all(releases).await;
    }

    /// Start the bounded, keeper-owned acquisition for `owner`.
    ///
    /// The task belongs to the entry (and is aborted with it), never to the
    /// request that asked for it: a cancelled compile must not strand an owner
    /// in `Acquiring`, and an accepted lease must not be lost with the request
    /// that triggered it.
    fn begin_acquire(&self, state: &mut Registry, owner: BuildOwner) {
        // Insert and retain the task handle under the same lock, without a
        // cancellation point that could strand Acquiring or detach its owner.
        let entry = state.entries.get_mut(&owner).expect("newly tracked owner");
        entry.acquire = Some(spawn_acquire(
            &self.shared,
            owner,
            entry.lease_id.clone(),
            entry.generation,
        ));
    }
}

impl Drop for BuildLeaseKeeper {
    fn drop(&mut self) {
        // No orphan task outlives its keeper: stop the supervisor and any
        // acquisition that is still in flight (best effort: a contended lock
        // leaves at most one bounded acquisition to finish on its own).
        self.supervisor.abort();
        if let Ok(mut state) = self.shared.state.try_lock() {
            for entry in state.entries.values_mut() {
                if let Some(acquire) = entry.acquire.take() {
                    acquire.abort();
                }
            }
        }
    }
}

/// Result of trying to track one owner.
enum Tracked {
    Inserted,
    AlreadyTracked,
    Full,
    Closed,
}

/// One bounded acquisition, owned by the keeper rather than by the request
/// that asked for it. Dropping the requester leaves this task running, so the
/// entry always leaves `Acquiring`.
fn spawn_acquire(
    shared: &Arc<Shared>,
    owner: BuildOwner,
    lease_id: String,
    generation: u64,
) -> JoinHandle<()> {
    let task_shared = Arc::clone(shared);
    shared.runtime.spawn(async move {
        let started = Instant::now();
        let result = match tokio::time::timeout(
            task_shared.timings.rpc,
            task_shared
                .sender
                .send(BuildLeaseOperation::Acquire, &lease_id),
        )
        .await
        {
            Ok(result) => result,
            Err(_) => Err(BuildLeaseFailure::ambiguous(anyhow!(
                "build lease acquire timed out after {:?}",
                task_shared.timings.rpc
            ))),
        };
        apply_acquire(&task_shared, owner, generation, &lease_id, started, result).await;
    })
}

/// Commit the outcome of one acquisition.
///
/// This always moves the entry out of `Acquiring`, whatever the wire did, so a
/// cancelled request can never leave an owner pending forever.
async fn apply_acquire(
    shared: &Arc<Shared>,
    owner: BuildOwner,
    generation: u64,
    lease_id: &str,
    started: Instant,
    result: std::result::Result<BuildLeaseOutcome, BuildLeaseFailure>,
) {
    let now = Instant::now();
    {
        let mut state = shared.state.lock().await;
        let Some(entry) = state.entries.get_mut(&owner) else {
            return;
        };
        if entry.generation != generation || entry.lease_id != lease_id {
            return;
        }
        entry.acquire = None;
        match result {
            Ok(BuildLeaseOutcome::Held { ttl_seconds, .. }) => {
                let expires_at = granted_until(started, ttl_seconds);
                if expires_at <= now {
                    // The grant already reached its conservative expiry: this
                    // daemon never held retention it can still rely on, and it
                    // must not schedule a renewal that is already late.
                    entry.phase = Phase::Lost;
                    entry.held_until = None;
                    entry.next_renew = None;
                    debug!(
                        "build lease for pid {} expired before its grant was applied",
                        owner.pid
                    );
                } else {
                    entry.phase = Phase::Held;
                    entry.held_until = Some(expires_at);
                    entry.next_renew = Some(next_renew_at(now, shared.timings.renew, expires_at));
                    debug!("build lease acquired for pid {}", owner.pid);
                }
            }
            Ok(BuildLeaseOutcome::Released { .. }) => {
                entry.phase = Phase::Unleased;
                debug!("build lease acquire answered with a release response");
            }
            Err(failure) => {
                // A lease that could not be obtained is a local condition (the
                // build simply runs without retention); lease *loss* is what is
                // worth a warning.
                entry.phase = Phase::Unleased;
                debug!(
                    "build lease acquire failed for pid {}: {failure}",
                    owner.pid
                );
            }
        }
    }
    shared.notify.notify_waiters();
}

async fn supervise(shared: Arc<Shared>) {
    let mut ops: JoinSet<OpOutcome> = JoinSet::new();
    let mut next_tick = Instant::now() + shared.timings.liveness;
    loop {
        tokio::select! {
            _ = shared.notify.notified() => {}
            _ = tokio::time::sleep_until(tokio::time::Instant::from_std(next_tick)) => {}
            Some(result) = ops.join_next(), if !ops.is_empty() => {
                match result {
                    Ok(outcome) => apply_outcome(&shared, outcome).await,
                    Err(error) => debug!("build lease operation task failed: {error}"),
                }
            }
        }
        if shared.closed.load(Ordering::SeqCst) {
            break;
        }
        if Instant::now() >= next_tick {
            next_tick = Instant::now() + shared.timings.liveness;
            tick(&shared, &mut ops).await;
        }
    }
    ops.abort_all();
    while ops.join_next().await.is_some() {}
}

/// One liveness/renewal pass: owner exits are checked independently of any
/// in-flight renewal, and never while the registry lock is held (liveness
/// reads the kernel, and compile requests wait on that lock).
async fn tick(shared: &Arc<Shared>, ops: &mut JoinSet<OpOutcome>) {
    let now = Instant::now();
    // Snapshot the held owners under a short lock, with no I/O.
    let held: Vec<(BuildOwner, u64)> = {
        let state = shared.state.lock().await;
        state
            .order
            .iter()
            .filter_map(|key| {
                let entry = state.entries.get(key)?;
                (entry.phase == Phase::Held).then_some((*key, entry.generation))
            })
            .collect()
    };
    // Check liveness without the lock.
    let dead: Vec<BuildOwner> = held
        .iter()
        .map(|(owner, _)| *owner)
        .filter(|owner| !shared.reader.is_live(owner))
        .collect();
    let mut state = shared.state.lock().await;
    for (owner, generation) in held {
        let Some(entry) = state.entries.get_mut(&owner) else {
            continue;
        };
        if entry.generation != generation || entry.phase != Phase::Held {
            continue;
        }
        if dead.contains(&owner) {
            entry.phase = Phase::Releasing;
            entry.inflight = true;
            spawn_release(shared, ops, owner, entry.lease_id.clone(), entry.generation);
            continue;
        }
        if entry.held_until.is_some_and(|deadline| now >= deadline) {
            // The gateway lease has provably expired: stop mutating.
            entry.phase = Phase::Lost;
            entry.held_until = None;
            entry.next_renew = None;
            warn!(
                "build lease for pid {} expired without a successful renewal",
                owner.pid
            );
            continue;
        }
        if !entry.inflight && entry.next_renew.is_some_and(|at| now >= at) {
            entry.inflight = true;
            spawn_renew(shared, ops, owner, entry.lease_id.clone(), entry.generation);
        }
    }
}

fn spawn_renew(
    shared: &Arc<Shared>,
    ops: &mut JoinSet<OpOutcome>,
    owner: BuildOwner,
    lease_id: String,
    generation: u64,
) {
    let shared = Arc::clone(shared);
    ops.spawn(async move {
        let started = Instant::now();
        let result = match tokio::time::timeout(
            shared.timings.rpc,
            shared.sender.send(BuildLeaseOperation::Renew, &lease_id),
        )
        .await
        {
            Ok(result) => result,
            Err(_) => Err(BuildLeaseFailure::ambiguous(anyhow!(
                "build lease renew timed out after {:?}",
                shared.timings.rpc
            ))),
        };
        OpOutcome::Renew {
            owner,
            generation,
            started,
            result,
        }
    });
}

fn spawn_release(
    shared: &Arc<Shared>,
    ops: &mut JoinSet<OpOutcome>,
    owner: BuildOwner,
    lease_id: String,
    generation: u64,
) {
    let shared = Arc::clone(shared);
    ops.spawn(async move {
        let result = match tokio::time::timeout(
            shared.timings.rpc,
            shared.sender.send(BuildLeaseOperation::Release, &lease_id),
        )
        .await
        {
            Ok(result) => result,
            Err(_) => Err(BuildLeaseFailure::ambiguous(anyhow!(
                "build lease release timed out after {:?}",
                shared.timings.rpc
            ))),
        };
        OpOutcome::Release {
            owner,
            generation,
            result,
        }
    });
}

async fn apply_outcome(shared: &Arc<Shared>, outcome: OpOutcome) {
    let now = Instant::now();
    let mut state = shared.state.lock().await;
    match outcome {
        OpOutcome::Renew {
            owner,
            generation,
            started,
            result,
        } => {
            let Some(entry) = state.entries.get_mut(&owner) else {
                return;
            };
            if entry.generation != generation {
                return;
            }
            entry.inflight = false;
            match result {
                Ok(BuildLeaseOutcome::Held { ttl_seconds, .. }) => {
                    let expires_at = granted_until(started, ttl_seconds);
                    if expires_at <= now {
                        // The renewal landed at or after its own conservative
                        // expiry: nothing may be claimed, and no later renewal
                        // may be scheduled.
                        if entry.phase == Phase::Held {
                            entry.phase = Phase::Lost;
                            entry.held_until = None;
                            entry.next_renew = None;
                            debug!(
                                "build lease for pid {} expired before its renewal was applied",
                                owner.pid
                            );
                        }
                        return;
                    }
                    // A renewal that lands after the local expiry still proves
                    // the gateway lease is live, so it revives the entry. An
                    // owner that already exited (or never held a lease) is
                    // left alone.
                    if matches!(entry.phase, Phase::Held | Phase::Lost) {
                        entry.phase = Phase::Held;
                        entry.held_until = Some(expires_at);
                        entry.next_renew =
                            Some(next_renew_at(now, shared.timings.renew, expires_at));
                    }
                }
                Err(failure) if failure.is_unknown_lease() => {
                    // Definitive: the gateway no longer knows this lease.
                    // Retire it locally; never recreate it.
                    if entry.phase == Phase::Held {
                        entry.phase = Phase::Lost;
                        entry.held_until = None;
                        entry.next_renew = None;
                        warn!(
                            "build lease for pid {} is no longer known to the gateway",
                            owner.pid
                        );
                    }
                }
                Err(failure) => {
                    // Refused or ambiguous: never retry this mutation. The next
                    // cadence attempt is a fresh request, bounded so it never
                    // lands at or after the gateway lease's expiry.
                    if entry.phase == Phase::Held {
                        entry.next_renew = Some(match entry.held_until {
                            Some(expires_at) => {
                                next_renew_at(now, shared.timings.renew, expires_at)
                            }
                            None => now + shared.timings.renew,
                        });
                        debug!(
                            "build lease renewal for pid {} failed: {failure}",
                            owner.pid
                        );
                    }
                }
                Ok(BuildLeaseOutcome::Released { .. }) => {
                    if entry.phase == Phase::Held {
                        entry.next_renew = Some(match entry.held_until {
                            Some(expires_at) => {
                                next_renew_at(now, shared.timings.renew, expires_at)
                            }
                            None => now + shared.timings.renew,
                        });
                    }
                }
            }
        }
        OpOutcome::Release {
            owner,
            generation,
            result,
        } => {
            let stale = state
                .entries
                .get(&owner)
                .is_none_or(|entry| entry.generation != generation);
            if stale {
                return;
            }
            if let Err(failure) = result {
                debug!(
                    "build lease release for pid {} failed: {failure}",
                    owner.pid
                );
            }
            state.remove(&owner);
        }
    }
}

/// The daemon's distributed-client container is the production lease
/// transport: the keeper asks it for the currently selected client (QUIC or
/// the pinned HTTP client) and never falls back to another transport.
#[async_trait]
impl BuildLeaseSender for crate::server::DistClientContainer {
    async fn send(
        &self,
        operation: BuildLeaseOperation,
        lease_id: &str,
    ) -> std::result::Result<BuildLeaseOutcome, BuildLeaseFailure> {
        let client = self.get_client().await.map_err(|error| {
            BuildLeaseFailure::ambiguous(error.context("distributed client is unavailable"))
        })?;
        let Some(client) = client else {
            return Err(BuildLeaseFailure::ambiguous(anyhow!(
                "distributed compilation is disabled"
            )));
        };
        client.do_build_lease(operation, lease_id).await
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicU32, AtomicUsize};

    /// What a scripted answer is: a real outcome, or a failure with an
    /// optional gateway status (`None` = ambiguous).
    type ScriptedAnswer = std::result::Result<BuildLeaseOutcome, (Option<u16>, &'static str)>;

    /// Records every mutation and answers from a scripted queue.
    #[derive(Default)]
    struct MockSender {
        calls: Mutex<Vec<(BuildLeaseOperation, String)>>,
        answers: Mutex<VecDeque<ScriptedAnswer>>,
        ttl_seconds: Mutex<u64>,
        /// When set, an acquire waits for a permit before answering, so a test
        /// can cancel the requester while the acquisition is in flight.
        acquire_gate: Mutex<Option<Arc<tokio::sync::Semaphore>>>,
        /// When set, every mutation waits this long before answering.
        delay: Mutex<Option<Duration>>,
        notify: Notify,
    }

    impl MockSender {
        async fn calls(&self) -> Vec<(BuildLeaseOperation, String)> {
            self.calls.lock().await.clone()
        }

        async fn count(&self, operation: BuildLeaseOperation) -> usize {
            self.calls()
                .await
                .iter()
                .filter(|(called, _)| *called == operation)
                .count()
        }

        async fn push_answer(&self, answer: ScriptedAnswer) {
            self.answers.lock().await.push_back(answer);
        }

        async fn clear_answers(&self) {
            self.answers.lock().await.clear();
        }

        async fn set_ttl(&self, ttl_seconds: u64) {
            *self.ttl_seconds.lock().await = ttl_seconds;
        }

        async fn set_delay(&self, delay: Duration) {
            *self.delay.lock().await = Some(delay);
        }

        /// Hold every acquire until [`MockSender::release_acquires`].
        async fn hold_acquires(&self) -> Arc<tokio::sync::Semaphore> {
            let gate = Arc::new(tokio::sync::Semaphore::new(0));
            *self.acquire_gate.lock().await = Some(Arc::clone(&gate));
            gate
        }

        async fn release_acquires(&self, gate: &Arc<tokio::sync::Semaphore>) {
            gate.add_permits(1);
        }

        async fn wait_for_calls(&self, operation: BuildLeaseOperation, count: usize) {
            let deadline = Instant::now() + Duration::from_secs(10);
            while Instant::now() < deadline {
                if self.count(operation).await >= count {
                    return;
                }
                let _ =
                    tokio::time::timeout(Duration::from_millis(10), self.notify.notified()).await;
            }
            panic!(
                "timed out waiting for {count} {operation:?} calls, saw {:?}",
                self.calls().await
            );
        }
    }

    #[async_trait]
    impl BuildLeaseSender for MockSender {
        async fn send(
            &self,
            operation: BuildLeaseOperation,
            lease_id: &str,
        ) -> std::result::Result<BuildLeaseOutcome, BuildLeaseFailure> {
            self.calls
                .lock()
                .await
                .push((operation, lease_id.to_owned()));
            self.notify.notify_waiters();
            let gate = self.acquire_gate.lock().await.clone();
            if let (Some(gate), BuildLeaseOperation::Acquire) = (gate, operation) {
                let _ = gate.acquire().await;
            }
            let delay = *self.delay.lock().await;
            if let Some(delay) = delay {
                tokio::time::sleep(delay).await;
            }
            let scripted = self.answers.lock().await.pop_front();
            match scripted {
                Some(Ok(outcome)) => Ok(outcome),
                Some(Err((status, message))) => match status {
                    Some(status) => Err(BuildLeaseFailure::gateway(status, anyhow!(message))),
                    None => Err(BuildLeaseFailure::ambiguous(anyhow!(message))),
                },
                None => match operation {
                    BuildLeaseOperation::Acquire | BuildLeaseOperation::Renew => {
                        Ok(BuildLeaseOutcome::Held {
                            lease_id: lease_id.to_owned(),
                            ttl_seconds: *self.ttl_seconds.lock().await,
                        })
                    }
                    BuildLeaseOperation::Release => {
                        Ok(BuildLeaseOutcome::Released { released: true })
                    }
                },
            }
        }
    }

    /// Owner liveness under test control: every tracked owner is live until
    /// the test declares the process dead (or its pid reused).
    struct FakeReader {
        dead: AtomicBool,
        dead_pid: AtomicU32,
        checks: AtomicUsize,
    }

    impl FakeReader {
        fn always_live() -> Arc<Self> {
            Arc::new(Self {
                dead: AtomicBool::new(false),
                dead_pid: AtomicU32::new(0),
                checks: AtomicUsize::new(0),
            })
        }

        fn declare_dead(&self) {
            self.dead.store(true, Ordering::SeqCst);
        }

        /// Mark exactly one owner's process as gone (exited or reused).
        fn declare_pid_dead(&self, pid: u32) {
            self.dead_pid.store(pid, Ordering::SeqCst);
        }
    }

    impl OwnerReader for FakeReader {
        fn is_live(&self, owner: &BuildOwner) -> bool {
            self.checks.fetch_add(1, Ordering::SeqCst);
            !self.dead.load(Ordering::SeqCst) && owner.pid != self.dead_pid.load(Ordering::SeqCst)
        }
    }

    fn owner(pid: u32) -> BuildOwner {
        BuildOwner {
            pid,
            start_token: u64::from(pid) * 7,
            uid: build_owner::current_uid(),
        }
    }

    fn fast_timings() -> LeaseTimings {
        LeaseTimings {
            liveness: Duration::from_millis(25),
            renew: Duration::from_millis(150),
            rpc: Duration::from_secs(2),
        }
    }

    fn keeper(
        sender: Arc<MockSender>,
        reader: Arc<FakeReader>,
        timings: LeaseTimings,
    ) -> Arc<BuildLeaseKeeper> {
        BuildLeaseKeeper::with_parts(sender, reader, timings, &tokio::runtime::Handle::current())
    }

    #[test]
    fn lease_ids_are_256_bit_lowercase_hex() {
        let first = new_lease_id();
        let second = new_lease_id();
        assert_eq!(first.len(), 64);
        assert!(is_valid_lease_id(&first));
        assert!(is_valid_lease_id(&second));
        assert_ne!(first, second);
        assert!(!is_valid_lease_id(&first.to_uppercase()));
        assert!(!is_valid_lease_id(&first[..63]));
        assert!(!is_valid_lease_id(&format!("{first}0")));
        assert!(!is_valid_lease_id(
            "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"
        ));
    }

    #[test]
    fn responses_are_validated_explicitly() {
        let id = "a".repeat(64);
        let ok = decode_build_lease_response(
            BuildLeaseOperation::Acquire,
            &id,
            200,
            format!(r#"{{"lease_id":"{id}","ttl_seconds":90}}"#).as_bytes(),
        )
        .unwrap();
        assert_eq!(
            ok,
            BuildLeaseOutcome::Held {
                lease_id: id.clone(),
                ttl_seconds: 90
            }
        );
        // A different echoed id is never accepted.
        let other = "b".repeat(64);
        assert!(
            decode_build_lease_response(
                BuildLeaseOperation::Acquire,
                &id,
                200,
                format!(r#"{{"lease_id":"{other}","ttl_seconds":90}}"#).as_bytes(),
            )
            .unwrap_err()
            .is_ambiguous()
        );
        // Unknown fields, out of range TTLs and nonsense bodies are ambiguous.
        for body in [
            format!(r#"{{"lease_id":"{id}","ttl_seconds":90,"extra":1}}"#).into_bytes(),
            format!(r#"{{"lease_id":"{id}","ttl_seconds":0}}"#).into_bytes(),
            format!(r#"{{"lease_id":"{id}","ttl_seconds":100000}}"#).into_bytes(),
            b"not json".to_vec(),
            b"".to_vec(),
        ] {
            assert!(
                decode_build_lease_response(BuildLeaseOperation::Renew, &id, 200, &body)
                    .unwrap_err()
                    .is_ambiguous()
            );
        }
        // Every non-200 is a definitive gateway failure carrying its status.
        for status in [400u16, 401, 404, 409, 413, 503] {
            let failure =
                decode_build_lease_response(BuildLeaseOperation::Acquire, &id, status, b"nope")
                    .unwrap_err();
            assert_eq!(failure.status, Some(status));
            assert!(!failure.is_ambiguous());
        }
        assert!(
            decode_build_lease_response(BuildLeaseOperation::Renew, &id, 404, b"gone")
                .unwrap_err()
                .is_unknown_lease()
        );
        assert!(
            decode_build_lease_response(BuildLeaseOperation::Acquire, &id, 409, b"dup")
                .unwrap_err()
                .is_duplicate()
        );
        // Release answers carry only the released flag.
        assert_eq!(
            decode_build_lease_response(
                BuildLeaseOperation::Release,
                &id,
                200,
                br#"{"released":false}"#
            )
            .unwrap(),
            BuildLeaseOutcome::Released { released: false }
        );
        assert!(
            decode_build_lease_response(BuildLeaseOperation::Release, &id, 200, br#"{"nope":1}"#)
                .unwrap_err()
                .is_ambiguous()
        );
    }

    #[test]
    fn lease_capabilities_are_redacted_from_error_text() {
        let id = "0123456789abcdef".repeat(4);
        assert_eq!(id.len(), 64);
        assert_eq!(
            redact_lease_ids(&format!("bad request: lease {id} rejected")),
            "bad request: lease <lease-id> rejected"
        );
        // Only the exact capability shape is redacted.
        let upper = id.to_uppercase();
        assert_eq!(redact_lease_ids(&upper), upper);
        assert_eq!(redact_lease_ids("cafe"), "cafe");
        assert_eq!(redact_lease_ids(&"z".repeat(64)), "z".repeat(64));
        // A capability embedded in a longer token is still redacted.
        assert_eq!(redact_lease_ids(&format!("x{id}y")), "x<lease-id>y");
        // And a gateway answer can never leak the capability into a log line.
        let failure = decode_build_lease_response(
            BuildLeaseOperation::Renew,
            &id,
            404,
            format!("unknown lease {id}").as_bytes(),
        )
        .unwrap_err();
        assert!(!failure.to_string().contains(&id), "{failure}");
        assert!(failure.to_string().contains("<lease-id>"), "{failure}");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn one_lease_per_owner_is_deduplicated() {
        let sender = Arc::new(MockSender::default());
        sender.set_ttl(90).await;
        let reader = FakeReader::always_live();
        let keeper = keeper(Arc::clone(&sender), Arc::clone(&reader), fast_timings());
        let owner = owner(4242);

        keeper.ensure(&owner).await;
        keeper.ensure(&owner).await;
        keeper.ensure(&owner).await;
        assert_eq!(keeper.active_leases().await, 1);
        let calls = sender.calls().await;
        assert_eq!(calls.len(), 1, "unexpected calls: {calls:?}");
        assert_eq!(calls[0].0, BuildLeaseOperation::Acquire);
        assert!(is_valid_lease_id(&calls[0].1));

        // Concurrent first requests collapse into the same lease.
        let second_owner = self::owner(4243);
        let mut tasks = Vec::new();
        for _ in 0..8 {
            let keeper = Arc::clone(&keeper);
            tasks.push(tokio::spawn(async move {
                keeper.ensure(&second_owner).await;
            }));
        }
        for task in tasks {
            task.await.unwrap();
        }
        assert_eq!(
            sender.count(BuildLeaseOperation::Acquire).await,
            2,
            "concurrent first requests acquired more than once: {:?}",
            sender.calls().await
        );
    }

    /// The compile request that triggers an acquisition does not own it: if it
    /// is cancelled while the acquire is in flight, the keeper still settles
    /// the entry, and the accepted lease is neither lost nor replayed.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_aborted_first_request_does_not_strand_or_replay_the_acquire() {
        let sender = Arc::new(MockSender::default());
        sender.set_ttl(90).await;
        let gate = sender.hold_acquires().await;
        let reader = FakeReader::always_live();
        let keeper = keeper(Arc::clone(&sender), Arc::clone(&reader), fast_timings());
        let owner = owner(9000);

        // A first compiler request that is cancelled mid-acquire.
        let request = tokio::spawn({
            let keeper = Arc::clone(&keeper);
            async move { keeper.ensure(&owner).await }
        });
        sender.wait_for_calls(BuildLeaseOperation::Acquire, 1).await;
        request.abort();
        let _ = request.await;

        // The keeper-owned acquisition still settles when the gateway answers.
        sender.release_acquires(&gate).await;
        keeper.ensure(&owner).await;
        assert_eq!(
            keeper.active_leases().await,
            1,
            "the accepted lease was lost with the cancelled request"
        );
        assert_eq!(
            sender.count(BuildLeaseOperation::Acquire).await,
            1,
            "the acquire was replayed: {:?}",
            sender.calls().await
        );

        // The settled lease still follows the owner's exit.
        reader.declare_dead();
        sender.wait_for_calls(BuildLeaseOperation::Release, 1).await;
        assert_eq!(keeper.active_leases().await, 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn leases_are_retained_across_local_only_gaps() {
        let sender = Arc::new(MockSender::default());
        sender.set_ttl(90).await;
        let reader = FakeReader::always_live();
        let keeper = keeper(Arc::clone(&sender), Arc::clone(&reader), fast_timings());
        let owner = owner(5000);

        keeper.ensure(&owner).await;
        assert_eq!(keeper.active_leases().await, 1);
        // No further compiler requests: the lease is renewed, never released.
        sender.wait_for_calls(BuildLeaseOperation::Renew, 3).await;
        assert_eq!(sender.count(BuildLeaseOperation::Release).await, 0);
        assert_eq!(keeper.active_leases().await, 1);
        let calls = sender.calls().await;
        assert!(
            calls.iter().all(|(_, lease_id)| lease_id == &calls[0].1),
            "renewals used a different capability: {calls:?}"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_owner_exit_releases_the_lease_and_stops_renewals() {
        let sender = Arc::new(MockSender::default());
        sender.set_ttl(90).await;
        let reader = FakeReader::always_live();
        let keeper = keeper(Arc::clone(&sender), Arc::clone(&reader), fast_timings());
        let owner = owner(6000);

        keeper.ensure(&owner).await;
        assert_eq!(keeper.active_leases().await, 1);
        // The owner exits (or its pid is reused by another process).
        reader.declare_dead();
        sender.wait_for_calls(BuildLeaseOperation::Release, 1).await;
        let renews_at_exit = sender.count(BuildLeaseOperation::Renew).await;
        tokio::time::sleep(Duration::from_millis(400)).await;
        assert_eq!(
            sender.count(BuildLeaseOperation::Renew).await,
            renews_at_exit
        );
        assert_eq!(keeper.active_leases().await, 0);
        assert_eq!(sender.count(BuildLeaseOperation::Release).await, 1);
        let calls = sender.calls().await;
        let released = calls
            .iter()
            .find(|(operation, _)| *operation == BuildLeaseOperation::Release)
            .unwrap();
        assert_eq!(released.1, calls[0].1, "released a different capability");
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_real_process_exit_is_observed_within_the_liveness_tick() {
        use crate::test::utils::{kill_process, owner_of_child, spawn_sleep_process};

        let sender = Arc::new(MockSender::default());
        sender.set_ttl(90).await;
        let keeper = BuildLeaseKeeper::with_parts(
            Arc::clone(&sender) as Arc<dyn BuildLeaseSender>,
            Arc::new(KernelOwnerReader),
            fast_timings(),
            &tokio::runtime::Handle::current(),
        );
        let mut child = spawn_sleep_process();
        let owner = owner_of_child(&child);
        keeper.ensure(&owner).await;
        assert_eq!(keeper.active_leases().await, 1);
        kill_process(&mut child);
        sender.wait_for_calls(BuildLeaseOperation::Release, 1).await;
        assert_eq!(keeper.active_leases().await, 0);
        assert_eq!(sender.count(BuildLeaseOperation::Release).await, 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_definitive_unknown_renewal_retires_the_lease() {
        let sender = Arc::new(MockSender::default());
        sender.set_ttl(90).await;
        let reader = FakeReader::always_live();
        let keeper = keeper(Arc::clone(&sender), Arc::clone(&reader), fast_timings());
        let owner = owner(7000);
        keeper.ensure(&owner).await;
        assert_eq!(keeper.active_leases().await, 1);
        // The gateway forgets the lease: the next renewal answers 404.
        sender.clear_answers().await;
        sender
            .push_answer(Err((Some(404), "unknown or expired lease")))
            .await;
        sender.wait_for_calls(BuildLeaseOperation::Renew, 1).await;
        // Retired locally: no recreation, no release, no further renewals.
        let renews = sender.count(BuildLeaseOperation::Renew).await;
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert_eq!(sender.count(BuildLeaseOperation::Renew).await, renews);
        assert_eq!(sender.count(BuildLeaseOperation::Acquire).await, 1);
        assert_eq!(sender.count(BuildLeaseOperation::Release).await, 0);
        assert_eq!(keeper.active_leases().await, 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_failed_acquire_is_never_retried() {
        let sender = Arc::new(MockSender::default());
        sender.set_ttl(90).await;
        let reader = FakeReader::always_live();
        let keeper = keeper(Arc::clone(&sender), Arc::clone(&reader), fast_timings());
        let owner = owner(8000);
        sender.push_answer(Err((None, "transport exploded"))).await;

        keeper.ensure(&owner).await;
        assert_eq!(keeper.active_leases().await, 0);
        keeper.ensure(&owner).await;
        keeper.ensure(&owner).await;
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(
            sender.count(BuildLeaseOperation::Acquire).await,
            1,
            "an ambiguous acquire must not be retried: {:?}",
            sender.calls().await
        );
        assert_eq!(sender.count(BuildLeaseOperation::Renew).await, 0);
        assert_eq!(sender.count(BuildLeaseOperation::Release).await, 0);
    }

    /// A 409 acquire is a definitive failure, not an admission: the owner is
    /// left unleased, nothing is renewed and nothing is released.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_duplicate_acquire_is_not_adopted() {
        let sender = Arc::new(MockSender::default());
        sender.set_ttl(90).await;
        let reader = FakeReader::always_live();
        let keeper = keeper(Arc::clone(&sender), Arc::clone(&reader), fast_timings());
        let owner = owner(8100);
        sender
            .push_answer(Err((Some(409), "duplicate acquire")))
            .await;

        keeper.ensure(&owner).await;
        assert_eq!(
            keeper.active_leases().await,
            0,
            "a duplicate acquire must not hold a lease"
        );
        // Later requests do not retry it either.
        keeper.ensure(&owner).await;
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert_eq!(sender.count(BuildLeaseOperation::Acquire).await, 1);
        assert_eq!(
            sender.count(BuildLeaseOperation::Renew).await,
            0,
            "a failed acquisition must never be renewed: {:?}",
            sender.calls().await
        );
        assert_eq!(sender.count(BuildLeaseOperation::Release).await, 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn renewals_stop_once_the_lease_has_provably_expired() {
        let sender = Arc::new(MockSender::default());
        sender.set_ttl(1).await;
        let reader = FakeReader::always_live();
        let keeper = keeper(Arc::clone(&sender), Arc::clone(&reader), fast_timings());
        let owner = owner(8200);
        keeper.ensure(&owner).await;
        sender.wait_for_calls(BuildLeaseOperation::Renew, 1).await;
        // From now on every renewal is refused.
        sender.clear_answers().await;
        for _ in 0..8 {
            sender.push_answer(Err((Some(503), "maintenance"))).await;
        }
        // Wait past the one second TTL that the last success bought.
        tokio::time::sleep(Duration::from_millis(1500)).await;
        let settled = sender.count(BuildLeaseOperation::Renew).await;
        tokio::time::sleep(Duration::from_millis(600)).await;
        assert_eq!(
            sender.count(BuildLeaseOperation::Renew).await,
            settled,
            "renewals continued past the lease expiry: {:?}",
            sender.calls().await
        );
        assert_eq!(sender.count(BuildLeaseOperation::Release).await, 0);
        assert_eq!(keeper.active_leases().await, 0);
    }

    /// A grant's TTL is measured from the instant the mutation was *sent*, so a
    /// slow answer must never extend retention past the gateway's own expiry.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_grant_that_expires_before_its_answer_is_never_held() {
        let sender = Arc::new(MockSender::default());
        sender.set_ttl(1).await;
        sender.set_delay(Duration::from_millis(1200)).await;
        let reader = FakeReader::always_live();
        let keeper = keeper(Arc::clone(&sender), Arc::clone(&reader), fast_timings());
        let owner = owner(95_000);

        // The acquire is answered after its own one second TTL has passed.
        keeper.ensure(&owner).await;
        assert_eq!(
            keeper.active_leases().await,
            0,
            "a grant that already expired must not be held"
        );
        let renews = sender.count(BuildLeaseOperation::Renew).await;
        tokio::time::sleep(Duration::from_millis(400)).await;
        assert_eq!(
            sender.count(BuildLeaseOperation::Renew).await,
            renews,
            "an already expired grant must not be renewed: {:?}",
            sender.calls().await
        );
        assert_eq!(sender.count(BuildLeaseOperation::Release).await, 0);
    }

    /// The same conservatism for renewals: a renewal answered after its own
    /// conservative expiry retires the lease instead of claiming it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_renewal_that_expires_before_its_answer_is_retired() {
        let sender = Arc::new(MockSender::default());
        sender.set_ttl(1).await;
        let reader = FakeReader::always_live();
        let keeper = keeper(Arc::clone(&sender), Arc::clone(&reader), fast_timings());
        let owner = owner(95_100);
        keeper.ensure(&owner).await;
        assert_eq!(keeper.active_leases().await, 1);

        // The first renewal is answered only after the grant it renews expired.
        sender.set_delay(Duration::from_millis(1200)).await;
        sender.wait_for_calls(BuildLeaseOperation::Renew, 1).await;
        let deadline = Instant::now() + Duration::from_secs(10);
        while keeper.active_leases().await != 0 && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(
            keeper.active_leases().await,
            0,
            "an expired renewal was still held"
        );
        let renews = sender.count(BuildLeaseOperation::Renew).await;
        tokio::time::sleep(Duration::from_millis(400)).await;
        assert_eq!(
            sender.count(BuildLeaseOperation::Renew).await,
            renews,
            "renewals continued after the lease expired: {:?}",
            sender.calls().await
        );
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_foreign_or_dead_owner_claims_no_lease() {
        use crate::test::utils::{kill_process, owner_of_child, spawn_sleep_process, wait_until};

        let sender = Arc::new(MockSender::default());
        sender.set_ttl(90).await;
        let keeper = BuildLeaseKeeper::with_parts(
            Arc::clone(&sender) as Arc<dyn BuildLeaseSender>,
            Arc::new(KernelOwnerReader),
            fast_timings(),
            &tokio::runtime::Handle::current(),
        );
        let mut dead = spawn_sleep_process();
        let dead_owner = owner_of_child(&dead);
        kill_process(&mut dead);
        assert!(
            wait_until(Duration::from_secs(10), || {
                build_owner::read_process_identity(dead_owner.pid).is_none()
            }),
            "the exited owner still reports a kernel identity"
        );

        // A dead owner and the daemon's own process never reach the gateway.
        keeper.ensure(&dead_owner).await;
        let own = BuildOwner {
            pid: std::process::id(),
            start_token: build_owner::read_process_identity(std::process::id())
                .expect("own identity")
                .start_token,
            uid: build_owner::current_uid(),
        };
        keeper.ensure(&own).await;
        assert_eq!(sender.calls().await.len(), 0);
        assert_eq!(keeper.active_leases().await, 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_registry_is_bounded() {
        let sender = Arc::new(MockSender::default());
        sender.set_ttl(90).await;
        let reader = FakeReader::always_live();
        let keeper = keeper(Arc::clone(&sender), Arc::clone(&reader), fast_timings());
        for index in 0..MAX_TRACKED_OWNERS {
            keeper.ensure(&owner(10_000 + index as u32)).await;
        }
        assert_eq!(keeper.active_leases().await, MAX_TRACKED_OWNERS);
        assert_eq!(
            sender.count(BuildLeaseOperation::Acquire).await,
            MAX_TRACKED_OWNERS
        );
        // Every tracked owner holds a live lease: a new owner is refused
        // rather than evicting one.
        keeper.ensure(&owner(20_000)).await;
        assert_eq!(keeper.active_leases().await, MAX_TRACKED_OWNERS);
        assert_eq!(
            sender.count(BuildLeaseOperation::Acquire).await,
            MAX_TRACKED_OWNERS,
            "the registry grew past its bound: {:?}",
            sender.calls().await
        );
    }

    /// A tombstone for an owner that is still alive must never be pruned: its
    /// first acquisition may still exist at the gateway, and tracking the
    /// owner again would mint a second capability for one build.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_saturated_registry_never_reacquires_a_live_tombstone() {
        let sender = Arc::new(MockSender::default());
        sender.set_ttl(90).await;
        let reader = FakeReader::always_live();
        let keeper = keeper(Arc::clone(&sender), Arc::clone(&reader), fast_timings());
        let live_owners = MAX_TRACKED_OWNERS - 1;

        // One owner whose acquire failed ambiguously, while its process lives.
        let failed = owner(60_000);
        sender.push_answer(Err((None, "transport exploded"))).await;
        keeper.ensure(&failed).await;
        assert_eq!(keeper.active_leases().await, 0);
        assert_eq!(sender.count(BuildLeaseOperation::Acquire).await, 1);

        // Fill the registry with live owners.
        for index in 0..live_owners {
            keeper.ensure(&owner(61_000 + index as u32)).await;
        }
        assert_eq!(keeper.active_leases().await, live_owners);
        assert_eq!(
            sender.count(BuildLeaseOperation::Acquire).await,
            live_owners + 1
        );

        // The registry is full of live entries: a new owner is refused and the
        // live tombstone stays, so nothing is replayed.
        keeper.ensure(&owner(70_000)).await;
        keeper.ensure(&failed).await;
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(keeper.active_leases().await, live_owners);
        assert_eq!(
            sender.count(BuildLeaseOperation::Acquire).await,
            live_owners + 1,
            "a live tombstone was pruned and its acquire replayed: {:?}",
            sender.calls().await
        );
    }

    /// Once a tombstone's owner has exited, the tombstone may be pruned, so a
    /// bounded registry keeps accepting new builds.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_dead_tombstone_is_pruned_for_a_new_owner() {
        let sender = Arc::new(MockSender::default());
        sender.set_ttl(90).await;
        let reader = FakeReader::always_live();
        let keeper = keeper(Arc::clone(&sender), Arc::clone(&reader), fast_timings());
        let live_owners = MAX_TRACKED_OWNERS - 1;

        let failed = owner(80_000);
        sender.push_answer(Err((None, "transport exploded"))).await;
        keeper.ensure(&failed).await;
        for index in 0..live_owners {
            keeper.ensure(&owner(81_000 + index as u32)).await;
        }
        assert_eq!(
            sender.count(BuildLeaseOperation::Acquire).await,
            live_owners + 1
        );

        // The tombstone's owner exits: the tombstone is now prunable.
        reader.declare_pid_dead(failed.pid);
        keeper.ensure(&owner(90_000)).await;
        assert_eq!(
            keeper.active_leases().await,
            live_owners + 1,
            "the pruned slot was not reused"
        );
        assert_eq!(
            sender.count(BuildLeaseOperation::Acquire).await,
            live_owners + 2,
            "the new owner was not tracked: {:?}",
            sender.calls().await
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn shutdown_releases_every_held_lease_once() {
        let sender = Arc::new(MockSender::default());
        sender.set_ttl(90).await;
        let reader = FakeReader::always_live();
        let keeper = keeper(Arc::clone(&sender), Arc::clone(&reader), fast_timings());
        keeper.ensure(&owner(30_000)).await;
        keeper.ensure(&owner(30_001)).await;
        assert_eq!(keeper.active_leases().await, 2);
        keeper.shutdown(Duration::from_secs(2)).await;
        let calls = sender.calls().await;
        let releases: Vec<&String> = calls
            .iter()
            .filter(|(operation, _)| *operation == BuildLeaseOperation::Release)
            .map(|(_, lease_id)| lease_id)
            .collect();
        assert_eq!(releases.len(), 2, "calls: {calls:?}");
        for (operation, lease_id) in &calls {
            if *operation == BuildLeaseOperation::Acquire {
                assert!(
                    releases.contains(&lease_id),
                    "unreleased capability {lease_id}"
                );
            }
        }
        // A closed keeper never acquires again, and shutdown is idempotent.
        keeper.ensure(&owner(30_002)).await;
        assert_eq!(sender.count(BuildLeaseOperation::Acquire).await, 2);
        keeper.shutdown(Duration::from_secs(2)).await;
        assert_eq!(sender.count(BuildLeaseOperation::Release).await, 2);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_dropped_keeper_leaves_no_renewal_task() {
        let sender = Arc::new(MockSender::default());
        sender.set_ttl(90).await;
        let reader = FakeReader::always_live();
        let keeper = keeper(Arc::clone(&sender), Arc::clone(&reader), fast_timings());
        keeper.ensure(&owner(40_000)).await;
        assert_eq!(keeper.active_leases().await, 1);
        drop(keeper);
        tokio::time::sleep(Duration::from_millis(50)).await;
        let calls_after_drop = sender.calls().await.len();
        tokio::time::sleep(Duration::from_millis(400)).await;
        assert_eq!(
            sender.calls().await.len(),
            calls_after_drop,
            "the supervisor kept mutating after the keeper was dropped"
        );
    }
}
