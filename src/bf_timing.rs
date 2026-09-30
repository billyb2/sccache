//! Opt-in stage timing for distributed compilation measurements.
//!
//! Enabled per process with `SCCACHE_BILLDFASTER_TIMING=1`. When the flag is
//! absent no clock reads happen and measuring compiles to a no-op. Each
//! measured stage emits exactly one line:
//!
//! ```text
//! [bf_timing] phase=do_run_http job_id=17 duration_ms=1234 bytes_in=5800032 bytes_out=2101
//! ```
//!
//! Only non-sensitive, bounded values are logged: durations, byte counts, job
//! ids and fixed phase names. Never source paths, command arguments,
//! credentials or certificate material. Lines are emitted through the existing
//! `log` macros (visible with `SCCACHE_LOG=info` or higher).

use std::env;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

static ENABLED: AtomicBool = AtomicBool::new(false);
static INIT: AtomicBool = AtomicBool::new(false);

fn timing_enabled() -> bool {
    if INIT.load(Ordering::Relaxed) {
        return ENABLED.load(Ordering::Relaxed);
    }
    let enabled = env::var("SCCACHE_BILLDFASTER_TIMING").as_deref() == Ok("1");
    ENABLED.store(enabled, Ordering::Relaxed);
    INIT.store(true, Ordering::Relaxed);
    enabled
}

/// One-line measurement of a single orchestration stage.
///
/// `start` returns `None` (and performs no clock read or allocation) unless
/// `SCCACHE_BILLDFASTER_TIMING=1` is set. Emitting happens exactly once, on
/// explicit `finish` or drop (whichever comes first), so error paths are
/// measured too.
pub struct BfTiming {
    phase: &'static str,
    job_id: Option<u64>,
    start: Instant,
    bytes_in: u64,
    bytes_out: u64,
    emitted: bool,
}

impl BfTiming {
    /// Start measuring a phase without a job correlator.
    pub fn start(phase: &'static str) -> Option<Self> {
        Self::start_with_job(phase, None)
    }

    /// Start measuring a phase with a job id correlator if available.
    pub fn start_with_job(phase: &'static str, job_id: Option<u64>) -> Option<Self> {
        if !timing_enabled() {
            return None;
        }
        Some(Self {
            phase,
            job_id,
            start: Instant::now(),
            bytes_in: 0,
            bytes_out: 0,
            emitted: false,
        })
    }

    /// Record the number of request-side bytes (inputs, body sent).
    pub fn set_bytes_in(&mut self, bytes: u64) {
        if !self.emitted {
            self.bytes_in = bytes;
        }
    }

    /// Record the number of response-side bytes (body received).
    pub fn set_bytes_out(&mut self, bytes: u64) {
        if !self.emitted {
            self.bytes_out = bytes;
        }
    }

    /// Emit the `[bf_timing]` line for this phase; a no-op if already emitted.
    pub fn finish(mut self) {
        if !self.emitted {
            self.emitted = true;
            self.emit();
        }
    }

    fn emit(&self) {
        let duration_ms = self.start.elapsed().as_millis() as u64;
        let job_id = self
            .job_id
            .map(|id| format!(" job_id={}", id))
            .unwrap_or_default();
        log::info!(
            "[bf_timing] phase={}{} duration_ms={} bytes_in={} bytes_out={}",
            self.phase,
            job_id,
            duration_ms,
            self.bytes_in,
            self.bytes_out
        );
    }
}

impl Drop for BfTiming {
    fn drop(&mut self) {
        if !self.emitted {
            self.emitted = true;
            self.emit();
        }
    }
}

/// Ergonomics for `Option<BfTiming>` call sites: all methods are no-ops when
/// the flag is absent (the `None` case) and delegate to [`BfTiming`] otherwise.
pub trait BfTimingOpt {
    fn set_bytes_in(&mut self, bytes: u64);
    fn set_bytes_out(&mut self, bytes: u64);
    fn finish(self);
}

impl BfTimingOpt for Option<BfTiming> {
    #[inline]
    fn set_bytes_in(&mut self, bytes: u64) {
        if let Some(t) = self {
            t.set_bytes_in(bytes);
        }
    }

    #[inline]
    fn set_bytes_out(&mut self, bytes: u64) {
        if let Some(t) = self {
            t.set_bytes_out(bytes);
        }
    }

    #[inline]
    fn finish(mut self) {
        if let Some(t) = self.take() {
            t.finish();
        }
    }
}
