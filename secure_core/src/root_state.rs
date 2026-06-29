//! RootState — the sole persistent cryptographic anchor.
//!
//! ## Threat model
//! Only 3 globals ever touch the physical medium:
//!   ROOT_STATE_CURR  : [u8; 32]  current active root key
//!   ROOT_STATE_PEND  : Option<[u8; 32]>  pending post-quantum replacement
//!   EPOCH_ID         : u32       current session epoch
//!
//! No per-message state, no look-ahead queue, no counter chain lives on disk.

use std::sync::Mutex;
use std::sync::OnceLock;
use zeroize::Zeroize;

// ---- globals ----

fn root_curr() -> &'static Mutex<[u8; 32]> {
    static C: OnceLock<Mutex<[u8; 32]>> = OnceLock::new();
    C.get_or_init(|| Mutex::new([0u8; 32]))
}

fn root_pend() -> &'static Mutex<Option<[u8; 32]>> {
    static P: OnceLock<Mutex<Option<[u8; 32]>>> = OnceLock::new();
    P.get_or_init(|| Mutex::new(None))
}

fn epoch() -> &'static Mutex<u32> {
    static E: OnceLock<Mutex<u32>> = OnceLock::new();
    E.get_or_init(|| Mutex::new(0))
}

// ---- internal helpers ----

pub fn set_root_state_curr(key: [u8; 32]) {
    let mut g = root_curr().lock().unwrap();
    *g = key;
}

pub fn read_root_state_curr() -> [u8; 32] {
    *root_curr().lock().unwrap()
}

pub fn set_root_state_pend(key: Option<[u8; 32]>) {
    let mut p = root_pend().lock().unwrap();
    *p = key;
}

pub fn read_root_state_pend() -> Option<[u8; 32]> {
    *root_pend().lock().unwrap()
}

pub fn read_epoch_id() -> u32 {
    *epoch().lock().unwrap()
}

pub fn set_epoch_id(id: u32) {
    let mut e = epoch().lock().unwrap();
    *e = id;
}

/// Atomically promote the pending root state to current and bump the epoch.
/// The old ROOT_STATE_CURR is zeroized in-place.
pub fn commit_evolution() -> u32 {
    let mut curr = root_curr().lock().unwrap();
    let mut pend = root_pend().lock().unwrap();
    let mut e = epoch().lock().unwrap();

    match *pend {
        None => return 1,
        Some(new_key) => {
            curr.zeroize();
            *curr = new_key;
            *pend = None;
            *e += 1;
            crate::message_cipher::reset_msg_counter();
            0
        }
    }
}

/// Atomically derive the next epoch key (HKDF-Extract roll-forward) under
/// all three locks.  Returns the new epoch ID or u32::MAX on error.
pub fn roll_epoch_forward(salt: &[u8], info: &[u8]) -> u32 {
    use hkdf::Hkdf;
    use sha2::Sha256;
    let mut curr = root_curr().lock().unwrap();
    let mut e = epoch().lock().unwrap();

    let hk = Hkdf::<Sha256>::new(Some(salt), &*curr);
    let mut okm = [0u8; 32];
    match hk.expand(info, &mut okm) {
        Ok(()) => {
            curr.zeroize();
            *curr = okm;
            *e += 1;
            crate::message_cipher::reset_msg_counter();
            *e
        }
        Err(_) => u32::MAX,
    }
}
