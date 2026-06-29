//! # secure_core  — RootState Ephemeral-Derivation Kernel
//!
//! Every message derives its encryption key on-the-fly from a single 256-bit
//! RootState. No per-message ratchet state, no lookahead queue, no counter chain.
//!
//! ## FFI rules (non-negotiable)
//! * Every data pointer crossing the boundary is `*const u8` / `*mut u8`.
//! * Every length is `u32`.
//! * Memory returned to the caller is heap-allocated; caller must free via
//!   `release_native_buffer`.
//! * No `String`, `Vec`, `struct`, or serialised format appears in a
//!   `#[no_mangle] pub extern "C"` signature.

// ---- modules ---------------------------------------------------------------

mod root_state;
mod init_module;
mod message_cipher;
mod tail_padding;
mod evolution;
mod anti_dos;
mod constant_flow;

// retained modules
mod memory_protection;
mod disk_wipe;
mod clock_align;

#[path = "virtual_volume.rs"]
mod vault;

// ---- std imports -----------------------------------------------------------

use std::alloc::{alloc, dealloc, Layout};
use std::sync::{Mutex, OnceLock};

// ---- vault singleton -------------------------------------------------------
// Kept for backward-compatible vault I/O.

static VFS: OnceLock<Mutex<vault::VirtualVolume>> = OnceLock::new();

fn with_vault_or<R>(default: R, f: impl FnOnce(&mut vault::VirtualVolume) -> R) -> R {
    let Some(mutex) = VFS.get() else { return default; };
    let Ok(mut v) = mutex.lock() else { return default; };
    f(&mut v)
}

// ---- internal helpers ------------------------------------------------------

pub(crate) fn vault_read_block(idx: u64, out: &mut [u8; 4068]) -> u32 {
    with_vault_or(1, |v| match v.read_block(idx, out) { Ok(()) => 0, Err(_) => 1 })
}
pub(crate) fn vault_write_block(idx: u64, data: &[u8; 4068]) -> u32 {
    with_vault_or(1, |v| match v.write_block(idx, data) { Ok(()) => 0, Err(_) => 1 })
}

// ============================================================================
//  Heap helpers
// ============================================================================

#[no_mangle]
pub extern "C" fn allocate_native_buffer(size: u32) -> *mut u8 {
    if size == 0 { return std::ptr::null_mut(); }
    let layout = Layout::array::<u8>(size as usize).unwrap();
    unsafe { alloc(layout) }
}

#[no_mangle]
pub extern "C" fn release_native_buffer(ptr: *mut u8, len: u32) {
    if ptr.is_null() || len == 0 { return; }
    let s = unsafe { std::slice::from_raw_parts_mut(ptr, len as usize) };
    s.fill(0);
    let layout = Layout::array::<u8>(len as usize).unwrap();
    unsafe { dealloc(ptr, layout); }
}

// ============================================================================
//  Vault I/O
// ============================================================================

#[no_mangle]
pub extern "C" fn init_virtual_volume(path_ptr: *const u8, path_len: u32, key_ptr: *const u8, key_len: u32, total: u64) -> u32 {
    if path_ptr.is_null() || key_ptr.is_null() || path_len == 0 || key_len < 32 { return 1; }
    let path = unsafe { std::str::from_utf8(std::slice::from_raw_parts(path_ptr, path_len as usize)) };
    let Ok(path) = path else { return 2 };
    let mut mk = [0u8; 32];
    unsafe { std::ptr::copy_nonoverlapping(key_ptr, mk.as_mut_ptr(), 32); }
    let vault = match vault::VirtualVolume::open_or_create(path, &mk, total) { Ok(v) => v, Err(_) => { mk.fill(0); return 3; } };
    mk.fill(0);
    let _ = VFS.set(Mutex::new(vault));
    0
}

#[no_mangle] pub extern "C" fn read_vault_blocks(start: u64, n: u32, out: *mut u8) -> u32 {
    if out.is_null() || n == 0 { return 0; }
    with_vault_or(0, |v| {
        let ps = vault::PAYLOAD_SIZE; let out = unsafe { std::slice::from_raw_parts_mut(out, n as usize * ps) };
        let mut c = 0u32;
        for i in 0..n as u64 {
            let mut buf = [0u8; vault::PAYLOAD_SIZE];
            if v.read_block(start + i, &mut buf).is_ok() { out[i as usize * ps..(i as usize + 1) * ps].copy_from_slice(&buf); c += 1; } else { break; }
        }
        c
    })
}
#[no_mangle] pub extern "C" fn write_vault_blocks(start: u64, n: u32, data: *const u8) -> u32 {
    if data.is_null() || n == 0 { return 0; }
    with_vault_or(0, |v| {
        let ps = vault::PAYLOAD_SIZE; let data = unsafe { std::slice::from_raw_parts(data, n as usize * ps) };
        let mut c = 0u32;
        for i in 0..n as u64 {
            let mut buf = [0u8; vault::PAYLOAD_SIZE];
            buf.copy_from_slice(&data[i as usize * ps..(i as usize + 1) * ps]);
            if v.write_block(start + i, &buf).is_ok() { c += 1; } else { break; }
        }
        c
    })
}
#[no_mangle] pub extern "C" fn allocate_vault_block() -> u64 { with_vault_or(u64::MAX, |v| v.allocate_block().unwrap_or(u64::MAX)) }
#[no_mangle] pub extern "C" fn free_vault_block(idx: u64) -> u32 { with_vault_or(1, |v| v.free_block(idx).map(|_| 0).unwrap_or(3)) }
#[no_mangle] pub extern "C" fn secure_erase_block(idx: u64) -> u32 {
    with_vault_or(1, |v| {
        let mut payload = [0u8; vault::PAYLOAD_SIZE];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut payload);
        if v.write_block(idx, &payload).is_err() { return 3; }
        v.free_block(idx).map(|_| 0).unwrap_or(3)
    })
}
#[no_mangle] pub extern "C" fn register_touch_offset(block: u64, offset: u32) -> u32 { with_vault_or(1, |v| { v.register_touch(block, offset); 0 }) }
#[no_mangle] pub extern "C" fn vault_total_blocks() -> u64 { with_vault_or(0, |v| v.total_blocks()) }
#[no_mangle] pub extern "C" fn vault_free_blocks() -> u64 { with_vault_or(0, |v| v.free_blocks()) }
// Canary honeytrap — blocks 995-999, seeded with known plaintext at vault creation.
static CANARY_INTACT: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

#[no_mangle] pub extern "C" fn validate_canary_slots() -> u32 {
    with_vault_or(1, |v| {
        for b in 995..=999 {
            let mut buf = [0u8; vault::PAYLOAD_SIZE];
            if v.read_block(b, &mut buf).is_err() { return 2; }
            if buf[0] != b'C' || buf[1] != b'A' || buf[2] != b'N' || buf[3] != b'A' || buf[4] != b'R' || buf[5] != b'Y' { return 2; }
        }
        CANARY_INTACT.store(true, std::sync::atomic::Ordering::SeqCst);
        0
    })
}
#[no_mangle] pub extern "C" fn canary_slots_intact() -> u32 { if CANARY_INTACT.load(std::sync::atomic::Ordering::SeqCst) { 1 } else { 0 } }
#[no_mangle] pub extern "C" fn init_canary_slots() -> u32 {
    with_vault_or(1, |v| {
        // Reserve blocks 994-999 in bitmap so allocator never hands them out
        for blk in 994u64..=999 { let _ = v.reserve_block(blk); }
        for slot in 0u8..5 {
            let mut buf = [0u8; vault::PAYLOAD_SIZE];
            buf[0] = b'C'; buf[1] = b'A'; buf[2] = b'N'; buf[3] = b'A'; buf[4] = b'R'; buf[5] = b'Y';
            buf[6] = slot; buf[7] = 0x01;
            rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut buf[8..]);
            if v.write_block(995 + slot as u64, &buf).is_err() { return 2; }
        }
        0
    })
}

#[no_mangle]
pub extern "C" fn purge_vault(path_ptr: *const u8, path_len: u32) -> u32 {
    if path_ptr.is_null() || path_len == 0 { return 1; }
    let path = unsafe { std::str::from_utf8(std::slice::from_raw_parts(path_ptr, path_len as usize)) };
    let Ok(path) = path else { return 2 };
    match disk_wipe::purge_entire_vault(path) {
        Ok(()) => { memory_protection::execute_panic_exit(); }
        Err(_) => 3,
    }
}

// ============================================================================
//  Root State + Init
// ============================================================================

#[no_mangle]
pub extern "C" fn init_root_state(a_ptr: *const u8, a_len: u32, b_ptr: *const u8, b_len: u32,
                                  pk_ptr: *const u8, pk_len: u32) -> u32 {
    if a_ptr.is_null() || b_ptr.is_null() || a_len == 0 || b_len == 0 { return 1; }
    let a = unsafe { std::slice::from_raw_parts(a_ptr, a_len as usize) };
    let b = unsafe { std::slice::from_raw_parts(b_ptr, b_len as usize) };
    let pk = if pk_ptr.is_null() || pk_len == 0 { &[] } else { unsafe { std::slice::from_raw_parts(pk_ptr, pk_len as usize) } };
    init_module::initialise_root_state(a, b, pk)
}
#[no_mangle] pub extern "C" fn get_epoch_id() -> u32 { root_state::read_epoch_id() }

#[no_mangle] pub extern "C" fn generate_id_stamp() -> u32 { init_module::generate_and_persist_id_stamp() }
#[no_mangle] pub extern "C" fn load_id_stamp(out: *mut u8, out_cap: u32) -> u32 {
    if out.is_null() || out_cap < 32 { return 1; }
    match init_module::read_id_stamp() { Some(s) => { unsafe { std::ptr::copy_nonoverlapping(s.as_ptr(), out, 32); } 0 } None => 1 }
}

// ============================================================================
//  Message encrypt / decrypt
// ============================================================================

#[no_mangle] pub extern "C" fn msg_counter_next() -> u64 { message_cipher::next_msg_seq() }
#[no_mangle] pub extern "C" fn msg_counter_current() -> u64 { message_cipher::current_msg_seq() }

#[no_mangle]
pub extern "C" fn derive_message_key(epoch: u32, msg_seq: u64) -> *mut u8 {
    let key = message_cipher::derive_message_key(epoch, msg_seq);
    let p = allocate_native_buffer(32);
    if !p.is_null() { unsafe { std::ptr::copy_nonoverlapping(key.as_ptr(), p, 32); } }
    p
}

#[no_mangle]
pub extern "C" fn encrypt_message(pt: *const u8, pt_len: u32, key: *const u8, stamp: *const u8,
    outgoing: u32, epoch: u32, msg_seq: u64, timestamp: u64, out_len: *mut u32) -> *mut u8 {
    if pt.is_null() || key.is_null() || stamp.is_null() || out_len.is_null() || pt_len == 0 { unsafe { if !out_len.is_null() { *out_len = 0; } } return std::ptr::null_mut(); }
    let pt = unsafe { std::slice::from_raw_parts(pt, pt_len as usize) };
    let k = unsafe { &*(key as *const [u8; 32]) };
    let s = unsafe { &*(stamp as *const [u8; 32]) };
    let ct = match message_cipher::encrypt(pt, k, s, outgoing != 0, epoch, msg_seq, timestamp) {
        Some(c) => c, None => { unsafe { *out_len = 0; } return std::ptr::null_mut(); }
    };
    unsafe { *out_len = ct.len() as u32; }
    let p = allocate_native_buffer(ct.len() as u32);
    if !p.is_null() { unsafe { std::ptr::copy_nonoverlapping(ct.as_ptr(), p, ct.len()); } }
    p
}

#[no_mangle]
pub extern "C" fn decrypt_message(ct: *const u8, ct_len: u32, key: *const u8, stamp: *const u8,
    outgoing: u32, epoch: u32, msg_seq: u64, timestamp: u64, out_len: *mut u32) -> *mut u8 {
    if ct.is_null() || key.is_null() || stamp.is_null() || out_len.is_null() || ct_len == 0 { unsafe { if !out_len.is_null() { *out_len = 0; } } return std::ptr::null_mut(); }
    let ct = unsafe { std::slice::from_raw_parts(ct, ct_len as usize) };
    let k = unsafe { &*(key as *const [u8; 32]) };
    let s = unsafe { &*(stamp as *const [u8; 32]) };
    match message_cipher::decrypt(ct, k, s, outgoing != 0, epoch, msg_seq, timestamp) {
        Some(pt) => { unsafe { *out_len = pt.len() as u32; } let p = allocate_native_buffer(pt.len() as u32); if !p.is_null() { unsafe { std::ptr::copy_nonoverlapping(pt.as_ptr(), p, pt.len()); } } p }
        None => { unsafe { *out_len = 0; } std::ptr::null_mut() }
    }
}

/// Decrypt with auto-commit: if current key fails and peer already committed
/// the pending evolution (msg epoch = local epoch + 1), auto-commits our side.
/// Returns plaintext on success.  `did_commit` receives 1 if auto-commit fired.
#[no_mangle]
pub extern "C" fn decrypt_with_auto_commit(
    ct: *const u8, ct_len: u32, stamp: *const u8,
    outgoing: u32, epoch: u32, msg_seq: u64, timestamp: u64,
    out_len: *mut u32, did_commit: *mut u32,
) -> *mut u8 {
    if ct.is_null() || stamp.is_null() || out_len.is_null() || ct_len == 0 { unsafe { if !out_len.is_null() { *out_len = 0; } if !did_commit.is_null() { *did_commit = 0; } } return std::ptr::null_mut(); }
    let ct = unsafe { std::slice::from_raw_parts(ct, ct_len as usize) };
    let s = unsafe { &*(stamp as *const [u8; 32]) };
    match message_cipher::try_decrypt_with_evolution(ct, s, outgoing != 0, epoch, msg_seq, timestamp) {
        Some((pt, committed)) => {
            unsafe { *out_len = pt.len() as u32; if !did_commit.is_null() { *did_commit = if committed { 1 } else { 0 }; } }
            let p = allocate_native_buffer(pt.len() as u32);
            if !p.is_null() { unsafe { std::ptr::copy_nonoverlapping(pt.as_ptr(), p, pt.len()); } }
            p
        }
        None => { unsafe { *out_len = 0; if !did_commit.is_null() { *did_commit = 0; } } std::ptr::null_mut() }
    }
}

#[no_mangle] pub extern "C" fn zeroize_key(ptr: *mut u8, len: u32) -> u32 { message_cipher::zeroize_key(ptr, len as usize); 0 }

// ============================================================================
//  Tail padding
// ============================================================================

#[no_mangle]
pub extern "C" fn add_tail_padding(data: *const u8, data_len: u32, out_len: *mut u32) -> *mut u8 {
    if data.is_null() || out_len.is_null() || data_len == 0 { unsafe { if !out_len.is_null() { *out_len = 0; } } return std::ptr::null_mut(); }
    let d = unsafe { std::slice::from_raw_parts(data, data_len as usize) };
    let padded = tail_padding::add_tail_padding(d);
    unsafe { *out_len = padded.len() as u32; }
    let p = allocate_native_buffer(padded.len() as u32);
    if !p.is_null() { unsafe { std::ptr::copy_nonoverlapping(padded.as_ptr(), p, padded.len()); } }
    p
}

#[no_mangle]
pub extern "C" fn strip_tail_padding(data: *const u8, data_len: u32, out_len: *mut u32) -> *mut u8 {
    if data.is_null() || out_len.is_null() || data_len == 0 { unsafe { if !out_len.is_null() { *out_len = 0; } } return std::ptr::null_mut(); }
    let d = unsafe { std::slice::from_raw_parts(data, data_len as usize) };
    match tail_padding::strip_tail_padding(d) {
        Some(pl) => { unsafe { *out_len = pl.len() as u32; } let p = allocate_native_buffer(pl.len() as u32); if !p.is_null() { unsafe { std::ptr::copy_nonoverlapping(pl.as_ptr(), p, pl.len()); } } p }
        None => { unsafe { *out_len = 0; } std::ptr::null_mut() }
    }
}

// ============================================================================
//  Post-quantum evolution
// ============================================================================

const ML_KEM_PK_LEN: u32 = 1568;
const ML_KEM_SK_LEN: u32 = 3168;

#[no_mangle] pub extern "C" fn evolution_generate_bob_keypair(out_pk: *mut u8, pk_cap: u32, out_sk: *mut u8, sk_cap: u32) -> u32 {
    if out_pk.is_null() || out_sk.is_null() || pk_cap < ML_KEM_PK_LEN || sk_cap < ML_KEM_SK_LEN { return 1; }
    let mut pk = vec![0u8; ML_KEM_PK_LEN as usize]; let mut sk = vec![0u8; ML_KEM_SK_LEN as usize];
    let r = evolution::generate_bob_keypair(&mut pk, &mut sk);
    if r == 0 { unsafe { std::ptr::copy_nonoverlapping(pk.as_ptr(), out_pk, pk.len()); std::ptr::copy_nonoverlapping(sk.as_ptr(), out_sk, sk.len()); } }
    r
}
#[no_mangle] pub extern "C" fn evolution_set_peer_public_key(pk: *const u8, pk_len: u32) -> u32 {
    if pk.is_null() || pk_len == 0 { return 1; }
    evolution::set_peer_public_key(unsafe { std::slice::from_raw_parts(pk, pk_len as usize) }); 0
}
#[no_mangle] pub extern "C" fn start_evolution() -> u32 { evolution::start_evolution() }
#[no_mangle] pub extern "C" fn kem_cipher_len() -> u32 { evolution::kem_cipher_len() as u32 }
#[no_mangle]
pub extern "C" fn get_kem_cipher(out: *mut u8, cap: u32) -> u32 {
    if out.is_null() || cap == 0 { return 1; }
    let mut buf = vec![0u8; cap as usize];
    let len = evolution::get_kem_cipher(&mut buf);
    if len == 0 { return 1; }
    unsafe { std::ptr::copy_nonoverlapping(buf.as_ptr(), out, len); }
    len as u32
}
#[no_mangle] pub extern "C" fn apply_peer_kem(ct: *const u8, ct_len: u32) -> u32 {
    if ct.is_null() || ct_len == 0 { return 1; }
    evolution::apply_peer_kem(unsafe { std::slice::from_raw_parts(ct, ct_len as usize) })
}
#[no_mangle] pub extern "C" fn commit_evolution() -> u32 { evolution::commit_evolution() }

// ============================================================================
//  Anti-DoS
// ============================================================================

#[no_mangle] pub extern "C" fn recover_after_loss(target_epoch: u32) -> u32 { anti_dos::recover_after_loss(target_epoch) }

// ============================================================================
//  Constant flow
// ============================================================================

#[no_mangle]
pub extern "C" fn build_noise_packet(out: *mut u8, out_len: *mut u32) -> u32 {
    if out.is_null() || out_len.is_null() { return 1; }
    let pkt = constant_flow::build_noise_packet();
    unsafe { *out_len = pkt.len() as u32; std::ptr::copy_nonoverlapping(pkt.as_ptr(), out, pkt.len()); }
    0
}
#[no_mangle] pub extern "C" fn start_constant_flow(cb: constant_flow::TxCallback) -> u32 {
    if cb as *const () == std::ptr::null() { return 1; }
    constant_flow::start_constant_flow(cb)
}
#[no_mangle] pub extern "C" fn stop_constant_flow() -> u32 { constant_flow::stop_constant_flow() }

// ============================================================================
//  Clock align
// ============================================================================

#[no_mangle] pub extern "C" fn init_clock_align() { clock_align::init(); }
#[no_mangle] pub extern "C" fn estimated_clock_skew() -> i64 { clock_align::skew() }
