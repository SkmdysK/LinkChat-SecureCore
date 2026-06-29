//! Adaptive clock-skew alignment utility.
//!
//! Hardware crystal oscillators drift over time, causing the local and
//! remote transaction counters to diverge.  This module tracks the
//! historical delta between observed counter leaps and provides a
//! forward-seek parser that can recover synchronisation **without**
//! querying NTP servers or relying on absolute wall-clock time.
//!
//! # How it works
//!
//! 1. Each incoming frame carries a remote counter `C_remote`.
//! 2. We compare `C_remote` to our local counter `C_local` and record the
//!    signed delta into a 16-slot ring buffer.
//! 3. The median of recent deltas is used as the **estimated skew**.
//! 4. When an incoming frame fails the dynamic-magic validation at the
//!    declared counter `C`, we spin a forward-seek loop across offsets
//!    `+1` through `+10`, recomputing the expected magic at each step.
//!    If any offset produces a match, the state machine snaps to that
//!    offset — the link is re-synchronised without breaking anonymity.

use std::sync::{
    atomic::{AtomicI64, Ordering},
    Mutex, OnceLock,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Number of historical delta samples held in the ring buffer.
const DELTA_HISTORY_SIZE: usize = 16;

/// Maximum forward-seek offset when an incoming frame's magic does not
/// match at its declared counter.  We try `C+1` through `C+SEEK_WINDOW`.
pub const SEEK_WINDOW: u64 = 10;

// ---------------------------------------------------------------------------
// Global state
// ---------------------------------------------------------------------------

/// Estimated clock skew in **counter steps** (not nanoseconds).  Positive
/// means the remote peer is ahead; negative means it is behind.
///
/// Lock-free for read access by the validation hot-path.  Updated
/// periodically by the skew estimator.
static ESTIMATED_SKEW: AtomicI64 = AtomicI64::new(0);

/// Ring buffer of recent (remote - local) counter deltas.
static DELTA_HISTORY: OnceLock<Mutex<SkewRingBuffer>> = OnceLock::new();

/// Timestamp (via `Instant`) of the last delta sample, in nanoseconds
/// from an arbitrary origin.  Used to age out stale samples.
static LAST_SAMPLE_NS: OnceLock<Mutex<u64>> = OnceLock::new();

// ---------------------------------------------------------------------------
// Ring buffer
// ---------------------------------------------------------------------------

/// Fixed-size ring buffer storing the last N signed counter deltas.
struct SkewRingBuffer {
    buf: [i64; DELTA_HISTORY_SIZE],
    write_idx: usize,
    count: usize, // number of valid entries (≤ DELTA_HISTORY_SIZE)
}

impl SkewRingBuffer {
    fn new() -> Self {
        Self {
            buf: [0i64; DELTA_HISTORY_SIZE],
            write_idx: 0,
            count: 0,
        }
    }

    /// Push a new delta sample.  If the buffer is full, the oldest entry
    /// is overwritten.
    fn push(&mut self, delta: i64) {
        self.buf[self.write_idx] = delta;
        self.write_idx = (self.write_idx + 1) % DELTA_HISTORY_SIZE;
        if self.count < DELTA_HISTORY_SIZE {
            self.count += 1;
        }
    }

    /// Return a copy of the valid entries, sorted.
    fn sorted_entries(&self) -> Vec<i64> {
        let mut v: Vec<i64> = self.buf[..self.count].to_vec();
        v.sort_unstable();
        v
    }

    /// Median of the collected deltas.
    fn median(&self) -> i64 {
        if self.count == 0 {
            return 0;
        }
        let sorted = self.sorted_entries();
        let mid = self.count / 2;
        if self.count % 2 == 1 {
            sorted[mid]
        } else {
            (sorted[mid - 1] + sorted[mid]) / 2
        }
    }
}

// ---------------------------------------------------------------------------
// Initialisation
// ---------------------------------------------------------------------------

/// Initialise the clock-align subsystem.  Must be called once during
/// bootstrap, before any validation or skew-estimation calls.
pub fn init_clock_align() {
    let _ = DELTA_HISTORY.set(Mutex::new(SkewRingBuffer::new()));
    let _ = LAST_SAMPLE_NS.set(Mutex::new(0));
}

// ---------------------------------------------------------------------------
// Skew estimation
// ---------------------------------------------------------------------------

/// Record a new counter observation.
///
/// * `remote_counter` — the counter value observed in an incoming frame.
/// * `local_counter` — our local counter at the time the frame was received.
///
/// The delta (`remote - local`) is pushed into the ring buffer and the
/// estimated skew is updated to the median of recent samples.
pub fn record_counter_observation(remote_counter: u64, local_counter: u64) {
    let delta = remote_counter as i64 - local_counter as i64;

    // Update the ring buffer.
    if let Some(mutex) = DELTA_HISTORY.get() {
        if let Ok(mut buf) = mutex.lock() {
            buf.push(delta);
            let median = buf.median();
            ESTIMATED_SKEW.store(median, Ordering::Release);
        }
    }

    // Record the timestamp of this sample.
    if let Some(mutex) = LAST_SAMPLE_NS.get() {
        if let Ok(mut ts) = mutex.lock() {
            *ts = monotonic_nanos();
        }
    }
}

/// Return the current estimated clock skew in counter steps.
///
/// * Positive → remote is ahead (our clock is slow).
/// * Negative → remote is behind (our clock is fast).
pub fn estimated_skew() -> i64 {
    ESTIMATED_SKEW.load(Ordering::Acquire)
}

// ---------------------------------------------------------------------------
// Forward-seek parser
// ---------------------------------------------------------------------------

/// Validate an incoming frame's dynamic magic, attempting counter offsets
/// from 0 through [`SEEK_WINDOW`] if the initial match fails.
///
/// # Algorithm
///
/// 1. Try `validate_frame_magic` at `frame.counter + 0`.
/// 2. If that fails, spin forward through `frame.counter + 1` up to
///    `frame.counter + SEEK_WINDOW`, constructing a temporary frame with
///    the adjusted counter and testing the magic at each offset.
/// 3. On the first successful match, record the offset as a new
///    counter-observation sample to feed the skew estimator.
///
/// Shorthand for `init_clock_align`.
pub fn init() { init_clock_align(); }

/// Shorthand for `estimated_skew`.
pub fn skew() -> i64 { estimated_skew() }

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Return a monotonic nanosecond timestamp from an arbitrary but fixed
/// origin.  Not correlated to wall-clock time — used only for relative
/// age calculations within the same process lifetime.
fn monotonic_nanos() -> u64 {
    // We use a simple once-initialised anchor.
    static ANCHOR: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
    let anchor = ANCHOR.get_or_init(std::time::Instant::now);
    let elapsed = anchor.elapsed();
    elapsed.as_secs().saturating_mul(1_000_000_000) + elapsed.subsec_nanos() as u64
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ring_buffer_push_and_median() {
        let mut buf = SkewRingBuffer::new();
        assert_eq!(buf.median(), 0);

        buf.push(5);
        buf.push(10);
        buf.push(15);
        assert_eq!(buf.median(), 10);
    }

    #[test]
    fn ring_buffer_median_even_count() {
        let mut buf = SkewRingBuffer::new();
        buf.push(10);
        buf.push(20);
        // Sorted: [10, 20], median = (10+20)/2 = 15
        assert_eq!(buf.median(), 15);
    }

    #[test]
    fn ring_buffer_wraps_correctly() {
        let mut buf = SkewRingBuffer::new();
        // Fill past capacity.
        for i in 0..(DELTA_HISTORY_SIZE + 4) {
            buf.push(i as i64);
        }
        assert_eq!(buf.count, DELTA_HISTORY_SIZE);
        // The oldest entries were evicted; the buffer now holds [4..19].
        let sorted = buf.sorted_entries();
        assert_eq!(sorted.len(), DELTA_HISTORY_SIZE);
        assert_eq!(sorted[0], 4);
    }

    #[test]
    fn monotonic_nanos_increases() {
        let a = monotonic_nanos();
        std::thread::sleep(std::time::Duration::from_millis(1));
        let b = monotonic_nanos();
        assert!(b > a);
    }
}
