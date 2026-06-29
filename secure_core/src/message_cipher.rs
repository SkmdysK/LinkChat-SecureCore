//! Message encryption — on-demand symmetric derivation with built-in anti-replay.
//!
//! ## Protocol
//!   1. msg_seq = atomic_fetch_add(MSG_COUNTER, 1)  // per-epoch, never repeats
//!   2. Message_Key = HKDF-Expand(salt=RootState_curr,
//!        info=EpochID(4B LE) ∥ msg_seq(8B LE), info_str="LinkChat HKDF Expand")
//!   3. Ciphertext   = AES-256-GCM-Encrypt(plaintext, key=Message_Key,
//!        aad=[id_stamp ∥ direction(1B) ∥ epoch(4B LE) ∥ msg_seq(8B LE) ∥ timestamp(8B LE) ∥ proto_ver(2B LE)],
//!        nonce=OsRng_12B)
//!   4. Wire format  = [12B nonce ∥ ciphertext ∥ 16B gcm_tag]
//!   5. Message_Key + key material are zeroized immediately after use.
//!
//! ## Anti-replay
//!   msg_seq is globally unique per epoch.  The CALLER (Swift layer) is responsible
//!   for tracking `[epoch, max_seq_seen]` and rejecting seq <= max_seq_seen.
//!   The Rust layer does NOT maintain persistent replay state across restarts.
//!
//! ## Per-message forward secrecy (within epoch)
//!   msg_seq guarantees every message key in an epoch is cryptographically
//!   independent — knowing key_n does not reveal key_{n+1} (HKDF property).

use std::sync::atomic::{AtomicU64, Ordering};
use aes_gcm::{Aes256Gcm, Nonce};
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::aead::generic_array::GenericArray;
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroize;
use crate::root_state;

// ---- global message sequence counter ----

static MSG_COUNTER: AtomicU64 = AtomicU64::new(1);

/// Allocate the next message sequence number for this epoch.
/// Never returns 0 (0 = unset / error sentinel).
pub fn next_msg_seq() -> u64 {
    MSG_COUNTER.fetch_add(1, Ordering::SeqCst)
}

/// Reset the counter at epoch roll-over.  Called by commit_evolution / roll_epoch_forward.
pub fn reset_msg_counter() {
    MSG_COUNTER.store(1, Ordering::SeqCst);
}

/// Read current counter (for receiver-side replay check).
pub fn current_msg_seq() -> u64 {
    MSG_COUNTER.load(Ordering::SeqCst)
}

// ---- key derivation ----

/// Derive a 32-byte message key from an explicit root key (does NOT touch the global).
pub fn derive_message_key_from_root(root: &[u8; 32], epoch: u32, msg_seq: u64) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(root), b"LinkChat HKDF Expand");
    let mut info = [0u8; 12];
    info[..4].copy_from_slice(&epoch.to_le_bytes());
    info[4..12].copy_from_slice(&msg_seq.to_le_bytes());
    let mut okm = [0u8; 32];
    hk.expand(&info, &mut okm)
        .expect("HKDF-Expand: 32 bytes always within SHA-256 limit");
    okm
}

/// Derive a 32-byte message key from the current root state.
/// k = HKDF-Expand(salt=RootState_curr,
///     info=EpochID(4B LE) ∥ msg_seq(8B LE), info_str="LinkChat HKDF Expand")
pub fn derive_message_key(epoch: u32, msg_seq: u64) -> [u8; 32] {
    let mut curr = root_state::read_root_state_curr();
    let hk = Hkdf::<Sha256>::new(Some(&curr), b"LinkChat HKDF Expand");

    let mut info = [0u8; 12];
    info[..4].copy_from_slice(&epoch.to_le_bytes());
    info[4..12].copy_from_slice(&msg_seq.to_le_bytes());

    let mut okm = [0u8; 32];
    hk.expand(&info, &mut okm)
        .expect("HKDF-Expand: 32 bytes always within SHA-256 limit");
    curr.zeroize();
    okm
}

// ---- PCS auto-commit decrypt ----

/// Try decrypting with current RootState first.  If that fails, check whether
/// the peer has already committed an evolution (message epoch = local epoch + 1)
/// and try the pending RootState.  On success with the pending key, atomically
/// commit the evolution so both sides converge on the same RootState.
///
/// Returns `(plaintext, did_auto_commit: bool)` or None if both keys fail.
pub fn try_decrypt_with_evolution(
    wire: &[u8], id_stamp: &[u8; 32],
    outgoing: bool, epoch: u32, msg_seq: u64, timestamp: u64,
) -> Option<(Vec<u8>, bool)> {
    // Fast path: current root
    let mut curr = root_state::read_root_state_curr();
    let local_epoch = root_state::read_epoch_id();
    let mut curr_key = derive_message_key_from_root(&curr, epoch, msg_seq);
    if let Some(pt) = decrypt(wire, &curr_key, id_stamp, outgoing, epoch, msg_seq, timestamp) {
        curr.zeroize(); curr_key.zeroize();
        return Some((pt, false));
    }
    curr.zeroize(); curr_key.zeroize();

    // Slow path: try pending key if peer is ahead by one epoch
    if epoch == local_epoch + 1 {
        if let Some(mut pend) = root_state::read_root_state_pend() {
            let mut pend_key = derive_message_key_from_root(&pend, epoch, msg_seq);
            if let Some(pt) = decrypt(wire, &pend_key, id_stamp, outgoing, epoch, msg_seq, timestamp) {
                let committed = root_state::commit_evolution() == 0;
                pend.zeroize(); pend_key.zeroize();
                return Some((pt, committed));
            }
            pend.zeroize(); pend_key.zeroize();
        }
    }

    None
}

// ---- AES-256-GCM nonce (deterministic: unique per message) ----

fn build_nonce(epoch: u32, timestamp: u64, msg_seq: u64) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[..4].copy_from_slice(&epoch.to_le_bytes());
    n[4..12].copy_from_slice(&(timestamp ^ msg_seq).to_le_bytes());
    n
}

// ---- AAD construction ----

const PROTO_VERSION: u16 = 4;

/// AAD = [id_stamp(32B) ∥ direction(1B) ∥ epoch(4B LE) ∥ msg_seq(8B LE) ∥ timestamp(8B LE) ∥ proto_ver(2B LE)]
fn build_aad(id_stamp: &[u8; 32], outgoing: bool, epoch: u32, msg_seq: u64, timestamp: u64) -> Vec<u8> {
    let mut aad = Vec::with_capacity(32 + 1 + 4 + 8 + 8 + 2);
    aad.extend_from_slice(id_stamp);
    aad.push(if outgoing { 0 } else { 1 });
    aad.extend_from_slice(&epoch.to_le_bytes());
    aad.extend_from_slice(&msg_seq.to_le_bytes());
    aad.extend_from_slice(&timestamp.to_le_bytes());
    aad.extend_from_slice(&PROTO_VERSION.to_le_bytes());
    aad
}

// ---- encrypt / decrypt ----

/// Encrypt `plaintext` under `key`.  Nonce is deterministic from (epoch, timestamp, msg_seq).
/// Returns `[12B nonce | ciphertext | 16B tag]`, or None on encryption error.
pub fn encrypt(plaintext: &[u8], key: &[u8; 32], id_stamp: &[u8; 32],
               outgoing: bool, epoch: u32, msg_seq: u64, timestamp: u64) -> Option<Vec<u8>> {
    let mut key_arr = GenericArray::clone_from_slice(key);
    let cipher = Aes256Gcm::new(&key_arr);
    key_arr.zeroize();
    let nonce = build_nonce(epoch, timestamp, msg_seq);
    let aad = build_aad(id_stamp, outgoing, epoch, msg_seq, timestamp);
    let ct = cipher.encrypt(Nonce::from_slice(&nonce), Payload { msg: plaintext, aad: &aad }).ok()?;
    let mut out = Vec::with_capacity(12 + ct.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Some(out)
}

/// Decrypt a wire-format payload.  All AAD parameters must match encrypt exactly.
pub fn decrypt(wire: &[u8], key: &[u8; 32], id_stamp: &[u8; 32],
               outgoing: bool, epoch: u32, msg_seq: u64, timestamp: u64) -> Option<Vec<u8>> {
    if wire.len() < 28 { return None; }
    let (nonce_bytes, ct) = wire.split_at(12);
    let mut key_arr = GenericArray::clone_from_slice(key);
    let cipher = Aes256Gcm::new(&key_arr);
    key_arr.zeroize();
    let aad = build_aad(id_stamp, outgoing, epoch, msg_seq, timestamp);
    cipher.decrypt(Nonce::from_slice(nonce_bytes), Payload { msg: ct, aad: &aad }).ok()
}

// ---- zeroize helper ----

pub fn zeroize_key(ptr: *mut u8, len: usize) {
    if ptr.is_null() || len == 0 { return; }
    unsafe { std::slice::from_raw_parts_mut(ptr, len) }.zeroize();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let mut test_root = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut test_root);
        root_state::set_root_state_curr(test_root);

        let stamp = [1u8; 32];
        let seq = next_msg_seq();
        let key = derive_message_key(0, seq);
        let plain = b"Hello LinkChat !";
        let ct = encrypt(plain, &key, &stamp, true, 0, seq, 1000).expect("encrypt");
        let pt = decrypt(&ct, &key, &stamp, true, 0, seq, 1000).expect("roundtrip");
        assert_eq!(pt, plain);

        // Tampered AAD must reject
        assert!(decrypt(&ct, &key, &stamp, false, 0, seq, 1000).is_none());
        assert!(decrypt(&ct, &key, &stamp, true, 1, seq, 1000).is_none());
        // Replay with different seq MUST fail
        assert!(decrypt(&ct, &key, &stamp, true, 0, seq + 1, 1000).is_none());
    }

    #[test]
    fn msg_seq_monotonic() {
        let a = next_msg_seq();
        let b = next_msg_seq();
        assert!(b > a);
    }

    #[test]
    fn key_changes_with_seq() {
        let mut test_root = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut test_root);
        root_state::set_root_state_curr(test_root);

        let k1 = derive_message_key(0, 1);
        let k2 = derive_message_key(0, 2);
        assert_ne!(k1, k2);
    }
}
