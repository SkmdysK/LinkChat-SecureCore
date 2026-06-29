//! Background post-quantum key evolution via ML-KEM-1024.
//!
//! ## Three-phase protocol
//!
//! ### Phase 0 — Initialisation (out-of-band, USB-C)
//!   Bob generates an ML-KEM-1024 keypair.  Bob's public key is shared with
//!   Alice during the physical init handshake.
//!
//! ### Phase 1 — Pending (Alice)
//!   Alice encapsulates to Bob's public key:
//!     (kem_ct, shared_secret_S) = ML-KEM-1024::encapsulate(bob_pk)
//!     alice_trng            = OsRng(32 bytes)
//!     RootState_pend        = HKDF-Extract(salt=S || alice_trng, ikm=RootState_curr)
//!
//! ### Phase 2 — Exchange
//!   Alice sends kem_ct to Bob via TDLib channel (Swift bridge).
//!   Bob calls apply_peer_kem(kem_ct) which decapsulates with his secret key,
//!   derives the SAME RootState_pend on Bob's side.
//!
//! ### Phase 3 — Atomic commit
//!   Both sides call commit_evolution().  RootState_curr ← RootState_pend,
//!   EpochID += 1, old RootState_curr zeroized in place.

use hkdf::Hkdf;
use sha2::Sha256;
use rand::RngCore;
use rand::rngs::OsRng;
use std::sync::Mutex;
use std::sync::OnceLock;
use zeroize::Zeroize;
use crate::root_state;
use crate::memory_protection::SecureBuffer;

// ---- globals ----

struct EvolutionState {
    kem_cipher: Option<SecureBuffer>,
}

impl Zeroize for EvolutionState {
    fn zeroize(&mut self) {
        self.kem_cipher = None;
    }
}

fn evo_state() -> &'static Mutex<EvolutionState> {
    static S: OnceLock<Mutex<EvolutionState>> = OnceLock::new();
    S.get_or_init(|| Mutex::new(EvolutionState { kem_cipher: None }))
}

// Bob's keypair — PK is Vec<u8>, SK is SecureBuffer (auto-zeroize on drop).
fn bob_keys() -> &'static Mutex<(Vec<u8>, SecureBuffer)> {
    static K: OnceLock<Mutex<(Vec<u8>, SecureBuffer)>> = OnceLock::new();
    K.get_or_init(|| Mutex::new((vec![], SecureBuffer::new())))
}

// Bob's public key — copied from Bob's keypair during init, used by Alice.
fn bob_public_key() -> &'static Mutex<Vec<u8>> {
    static P: OnceLock<Mutex<Vec<u8>>> = OnceLock::new();
    P.get_or_init(|| Mutex::new(vec![]))
}

/// Generate Bob's ML-KEM-1024 keypair (called once during init).
/// `out_pk` receives the public key, `out_sk` receives the secret key.
pub fn generate_bob_keypair(out_pk: &mut [u8], out_sk: &mut [u8]) -> u32 {
    let keypair = pqc_kyber::keypair(&mut OsRng);
    let pk_vec = keypair.public.to_vec();
    let sk_buf = SecureBuffer::from_vec(keypair.secret.to_vec());
    out_pk[..pk_vec.len()].copy_from_slice(&pk_vec);
    out_sk[..sk_buf.len()].copy_from_slice(sk_buf.as_slice());
    let mut k = bob_keys().lock().unwrap();
    *k = (pk_vec, sk_buf);
    0
}

// Peer public key hash — set once at init, verified on every evolution.
fn peer_pk_hash() -> &'static Mutex<[u8; 32]> {
    static H: OnceLock<Mutex<[u8; 32]>> = OnceLock::new();
    H.get_or_init(|| Mutex::new([0u8; 32]))
}

/// Store Bob's public key on Alice's side (received out-of-band during init).
/// Also stores a SHA-256 hash binding for MITM detection.
pub fn set_peer_public_key(pk: &[u8]) {
    let mut p = bob_public_key().lock().unwrap();
    p.clear(); p.extend_from_slice(pk);
    // Bind: store hash for later verification
    use sha2::{Sha256, Digest};
    let hash: [u8; 32] = Sha256::digest(pk).into();
    *peer_pk_hash().lock().unwrap() = hash;
}

// ---- Phase 1: Alice ----

pub fn start_evolution() -> u32 {
    let mut curr = root_state::read_root_state_curr();
    let pk = bob_public_key().lock().unwrap();
    if pk.is_empty() { curr.zeroize(); return 2; }

    // Verify public key hasn't been swapped since init (constant-time compare)
    use sha2::{Sha256, Digest};
    let current_hash: [u8; 32] = Sha256::digest(pk.as_slice()).into();
    let stored_hash = *peer_pk_hash().lock().unwrap();
    let mut acc: u8 = 0;
    for i in 0..32 { acc |= current_hash[i] ^ stored_hash[i]; }
    if stored_hash != [0u8; 32] && acc != 0 {
        curr.zeroize(); return 5;
    }

    let (kem_ct, shared_secret) = match pqc_kyber::encapsulate(&pk, &mut OsRng) {
        Ok((ct, ss)) => (SecureBuffer::from_vec(ct.to_vec()), ss.to_vec()),
        Err(_) => { curr.zeroize(); return 1; }
    };

    let ss_arr: [u8; 32] = match shared_secret.as_slice().try_into() {
        Ok(a) => a,
        Err(_) => { curr.zeroize(); return 4; }
    };
    let derived = derive_pending_key(&ss_arr, &curr);
    curr.zeroize();
    root_state::set_root_state_pend(Some(derived));

    let mut state = evo_state().lock().unwrap();
    state.kem_cipher = Some(kem_ct);
    0
}

/// Both sides MUST produce the same key, so the salt is only the shared
/// secret S (common to both peers via ML-KEM).  Local TRNG is NOT included.
fn derive_pending_key(ss: &[u8; 32], curr: &[u8; 32]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(ss), curr);
    let mut okm = [0u8; 32];
    hk.expand(b"LinkChat Evolution", &mut okm).expect("HKDF-Extract");
    okm
}

pub fn get_kem_cipher(out: &mut [u8]) -> usize {
    let state = evo_state().lock().unwrap();
    match &state.kem_cipher {
        Some(buf) => { let len = buf.len().min(out.len()); out[..len].copy_from_slice(&buf.as_slice()[..len]); len }
        None => 0,
    }
}

pub fn kem_cipher_len() -> usize {
    evo_state().lock().unwrap().kem_cipher.as_ref().map_or(0, |b| b.len())
}

// ---- Phase 2: Bob ----

pub fn apply_peer_kem(kem_ct: &[u8]) -> u32 {
    let sk = { let k = bob_keys().lock().unwrap(); k.1.as_slice().to_vec() };
    if sk.is_empty() { return 3; }

    let shared_secret = match pqc_kyber::decapsulate(kem_ct, &sk) {
        Ok(ss) => ss,
        Err(_) => return 2,
    };
    let ss_arr: [u8; 32] = match shared_secret.as_slice().try_into() {
        Ok(a) => a,
        Err(_) => return 4,
    };

    let mut curr = root_state::read_root_state_curr();
    let derived = derive_pending_key(&ss_arr, &curr);
    curr.zeroize();
    root_state::set_root_state_pend(Some(derived));
    0
}

// ---- Phase 3: commit ----

pub fn commit_evolution() -> u32 { root_state::commit_evolution() }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_evolution_cycle() {
        let key = [1u8; 32];
        root_state::set_root_state_curr(key);
        root_state::set_epoch_id(0);

        let mut pk = vec![0u8; 1568];
        let mut sk = vec![0u8; 3168];
        assert_eq!(generate_bob_keypair(&mut pk, &mut sk), 0);

        set_peer_public_key(&pk);
        assert_eq!(start_evolution(), 0);
        let ct_len = kem_cipher_len();
        assert!(ct_len > 0);
        let mut ct = vec![0u8; ct_len];
        assert_eq!(get_kem_cipher(&mut ct), ct_len);

        // Both sides derive the SAME pending key from the same shared secret
        let pend_before = root_state::read_root_state_pend();
        assert!(pend_before.is_some());
        assert_eq!(apply_peer_kem(&ct), 0);
        let pend_after = root_state::read_root_state_pend();
        assert_eq!(pend_before, pend_after); // MUST be identical

        assert_eq!(commit_evolution(), 0);
        assert_eq!(root_state::read_epoch_id(), 1);
    }
}
