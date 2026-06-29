//! Constant-flow cover traffic engine.
//!
//! ## Design
//! Every 5 seconds (rigid), the engine fires.  If there is a real message queued,
//! it is sent.  Otherwise, a 4KB packet filled with OsRng white noise is sent.
//! All packets are exactly 4096 bytes.
//!
//! ## Mixnet concept
//! In the current implementation packets are passed to Swift via a callback
//! function pointer (the callback is responsible for actual I/O through TDLib).
//! In a future "large pool mixnet" release the callback would be replaced by a
//! mesh-network relay layer where every node relays every packet to every other
//! node at the same 5-second cadence, making source/destination analysis
//! impossible at the network layer.
//!
//! ## Feature gate
//! Compile with `--features constant_flow` to enable the background tokio task.
//! Without the feature flag, `start_constant_flow` and `stop_constant_flow`
//! return 1 (not supported in this build).

use rand::RngCore;
use rand::rngs::OsRng;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::sync::OnceLock;

const PACKET_SIZE: usize = 4096;
const INTERVAL_SECS: u64 = 5;

/// Callback type: `fn(data_ptr: *const u8, data_len: u32)` — Swift-side sender.
pub type TxCallback = unsafe extern "C" fn(*const u8, u32);

static RUNNING: AtomicBool = AtomicBool::new(false);

fn pending_payload() -> &'static Mutex<Option<Vec<u8>>> {
    static P: OnceLock<Mutex<Option<Vec<u8>>>> = OnceLock::new();
    P.get_or_init(|| Mutex::new(None))
}

fn tx_callback() -> &'static Mutex<Option<TxCallback>> {
    static C: OnceLock<Mutex<Option<TxCallback>>> = OnceLock::new();
    C.get_or_init(|| Mutex::new(None))
}

/// Build a 4KB white-noise packet on the native heap.
/// Caller is responsible for releasing via `release_native_buffer`.
pub fn build_noise_packet() -> Vec<u8> {
    let mut buf = vec![0u8; PACKET_SIZE];
    OsRng.fill_bytes(&mut buf);
    buf
}

/// Queue a real payload for the next timer tick.
pub fn queue_real_message(payload: &[u8]) {
    let mut q = pending_payload().lock().unwrap();
    *q = Some(payload.to_vec());
}

/// Start the background timer.  `cb` is the Swift-side transmit function.
pub fn start_constant_flow(cb: TxCallback) -> u32 {
    // Prevent multiple concurrent threads
    if RUNNING.load(Ordering::SeqCst) { return 1; }
    *tx_callback().lock().unwrap() = Some(cb);
    RUNNING.store(true, Ordering::SeqCst);

    let _ = std::thread::spawn(move || {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            while RUNNING.load(Ordering::SeqCst) {
                std::thread::sleep(std::time::Duration::from_secs(INTERVAL_SECS));
                if !RUNNING.load(Ordering::SeqCst) { break; }

                let packet: Vec<u8>;
                {
                    let mut q = pending_payload().lock().unwrap();
                    match q.take() {
                        Some(data) => {
                            let mut pkt = data;
                            if pkt.len() > PACKET_SIZE { pkt.truncate(PACKET_SIZE); }
                            let len = pkt.len();
                            pkt.resize(PACKET_SIZE, 0);
                            OsRng.fill_bytes(&mut pkt[len..]);
                            packet = pkt;
                        }
                        None => { packet = build_noise_packet(); }
                    }
                }

                if let Some(cb) = *tx_callback().lock().unwrap() {
                    unsafe { cb(packet.as_ptr(), packet.len() as u32); }
                }
            }
        }));
        if result.is_err() {
            RUNNING.store(false, Ordering::SeqCst);
            *tx_callback().lock().unwrap() = None;
        }
    });

    0
}

/// Stop the background timer.
pub fn stop_constant_flow() -> u32 {
    RUNNING.store(false, Ordering::SeqCst);
    *tx_callback().lock().unwrap() = None;
    let mut q = pending_payload().lock().unwrap();
    *q = None;
    0
}
