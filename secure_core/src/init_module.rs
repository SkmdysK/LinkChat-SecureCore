//! Initialisation module — out-of-band physical trust root.
//!
//! ## Threat model
//! Alice and Bob physically connect via USB-C + BLE (offline), exchange entropy
//! payloads and Bob's ML-KEM-1024 public key.  The odd/even byte interleave creates
//! RootState_init in shared memory without either peer ever seeing the full key alone.
//!
//! Bob's public key is bound permanently into ID_Stamp, locking the pairing to the
//! key material that will be used for all future ML-KEM evolutions.
//!
//! ## ID_Stamp
//! A 256-bit symmetric identity stamp: SHA-256(prefix || RootState_init || bob_pk).
//! Stored permanently in the vault (block 994, immediately before the 5 canary blocks).
//! Used as AAD in every AEAD envelope to bind messages to the pairing session.
//!
//! ## Protocol order (non-negotiable)
//!   1. Bob generates ML-KEM-1024 keypair (on his device)
//!   2. Bob sends entropy bytes + public key to Alice over USB-C
//!   3. Alice calls init_root_state(alice_entropy, bob_entropy, bob_pk)
//!   4. Alice calls generate_id_stamp()  ← includes bob_pk in hash
//!   5. Both sides now share identical ID_Stamp bound to the same public key
//!
//! ## Mixnet note (concept)
//! The KEM_Cipher payload from evolution.rs is transported through TDLib — Rust
//! never touches the network.

use sha2::{Sha256, Digest};
use zeroize::Zeroize;
use std::sync::Mutex;
use std::sync::OnceLock;
use crate::root_state;

// ---- Bob's public key (received during init) ----

fn bob_pk_store() -> &'static Mutex<Vec<u8>> {
    static P: OnceLock<Mutex<Vec<u8>>> = OnceLock::new();
    P.get_or_init(|| Mutex::new(vec![]))
}

/// Store Bob's ML-KEM-1024 public key (received out-of-band via USB-C during init).
pub fn store_bob_public_key(pk: &[u8]) {
    let mut p = bob_pk_store().lock().unwrap();
    p.clear(); p.extend_from_slice(pk);
}

/// Read a copy of Bob's stored public key.
fn read_bob_pk() -> Vec<u8> {
    bob_pk_store().lock().unwrap().clone()
}

// ---- interleave ----

pub fn odd_even_interleave(alice: &[u8], bob: &[u8]) -> Vec<u8> {
    let len = alice.len().min(bob.len());
    let mut out = Vec::with_capacity(len * 2);
    for i in 0..len {
        out.push(alice[i]);
        out.push(bob[i]);
    }
    out
}

// ---- entropy quality check ----

fn entropy_reject(data: &[u8]) -> bool {
    if data.len() < 64 { return true; }
    // Reject all-zeros (TRNG short-circuit to ground)
    if data.iter().all(|&b| b == 0) { return true; }
    // Reject all-same-byte (TRNG stuck-at-value)
    let first = data[0];
    if data.iter().all(|&b| b == first) { return true; }
    false
}

// ---- ID_Stamp (bound to Bob's public key) ----

/// ID_Stamp = SHA-256("LinkChat ID Stamp" || root_state_init || bob_pk)
pub fn compute_id_stamp(root_state_init: &[u8], bob_pk: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"LinkChat ID Stamp");
    h.update(root_state_init);
    h.update(bob_pk);
    h.finalize().into()
}

// ---- initialisation ----

/// Compute RootState_init from Alice + Bob entropy streams, store Bob's public key,
/// and load RootState into the global.
///
/// `bob_pk` is Bob's ML-KEM-1024 public key (1568 bytes), transferred out-of-band
/// alongside the entropy.  Must be non-empty.
pub fn initialise_root_state(alice: &[u8], bob: &[u8], bob_pk: &[u8]) -> u32 {
    // Entropy quality gate
    if entropy_reject(alice) || entropy_reject(bob) { return 2; }

    let mut interleaved = odd_even_interleave(alice, bob);
    if interleaved.len() < 64 {
        interleaved.zeroize();
        return 1;
    }

    // Bob's public key MUST be provided for ID_Stamp binding
    if bob_pk.is_empty() {
        interleaved.zeroize();
        return 3;
    }
    store_bob_public_key(bob_pk);

    let mut h = Sha256::new();
    h.update(b"LinkChat RootState Init");
    h.update(&interleaved);
    interleaved.zeroize();
    let key: [u8; 32] = h.finalize().into();
    root_state::set_root_state_curr(key);
    root_state::set_epoch_id(0);
    0
}

// ---- ID_Stamp persistence ----

pub fn generate_and_persist_id_stamp() -> u32 {
    let stamp = generate_id_stamp_from_curr();
    persist_id_stamp(&stamp)
}

/// Compute ID_Stamp from current root state + stored Bob public key.
pub fn generate_id_stamp_from_curr() -> [u8; 32] {
    let curr = root_state::read_root_state_curr();
    let pk = read_bob_pk();
    compute_id_stamp(&curr, &pk)
}

pub fn persist_id_stamp(stamp: &[u8; 32]) -> u32 {
    let mut buf = [0u8; 4068];
    buf[..32].copy_from_slice(stamp);
    crate::vault_write_block(994, &buf)
}

pub fn read_id_stamp() -> Option<[u8; 32]> {
    let mut buf = [0u8; 4068];
    if crate::vault_read_block(994, &mut buf) != 0 { return None; }
    let mut stamp = [0u8; 32];
    stamp.copy_from_slice(&buf[..32]);
    Some(stamp)
}
