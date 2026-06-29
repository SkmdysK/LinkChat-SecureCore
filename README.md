# SecureCore  — Absolute Blind Cryptographic Kernel

**Post-quantum, zero-server, peer-to-peer encrypted messaging backend.**

[![Rust](https://img.shields.io/badge/rust-1.70%2B-orange.svg)](https://www.rust-lang.org)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
**English** | [中文](README_CN.md)

SecureCore is the native cryptographic kernel of **LinkChat** — a messaging system designed for threat models where the adversary controls the network, the server, and eventually has access to a cryptographically-relevant quantum computer. It exposes a flat C ABI via 22 `extern "C"` functions designed to be called from Swift (iOS) or Kotlin (Android) via a thin FFI bridge.

## Table of Contents

- [Design Philosophy](#design-philosophy)
- [Theoretical Foundation](#theoretical-foundation)
- [Architecture](#architecture)
- [Module Overview](#module-overview)
- [Cryptographic Primitives](#cryptographic-primitives)
- [Key Lifecycle](#key-lifecycle)
- [Wire Formats](#wire-formats)
- [FFI Reference](#ffi-reference)
- [Error Codes](#error-codes)
- [Build & Integrate](#build--integrate)
- [Security Properties](#security-properties)
- [Comparison to Signal Protocol](#comparison-to-signal-protocol)
- [Known Limitations](#known-limitations)
- [License](#license)

---

## Design Philosophy

### 1. Three Globals Only

The entire persistent cryptographic state of a session is exactly three values:

```
ROOT_STATE_CURR  : [u8; 32]   — current active 256-bit root key
ROOT_STATE_PEND  : Option<[u8; 32]> — pending post-quantum replacement
EPOCH_ID         : u32        — session epoch counter
```

There is no per-message ratchet chain, no look-ahead key queue, no counter chain stored on disk. Every message key is derived on-the-fly via HKDF-SHA256 from `RootState_curr` combined with an atomically-incrementing per-epoch message sequence number.

### 2. Physical Trust Root

Initial key material is exchanged out-of-band via USB-C + BLE. Alice and Bob each contribute entropy bytes, which are odd/even-interleaved in shared memory and hashed via SHA-256 to produce the initial `RootState`. No asymmetric key exchange traffic exists for a future quantum computer to retroactively decrypt.

### 3. Post-Quantum Forward Secrecy

Key rotation uses **ML-KEM-1024** (NIST FIPS 203, Category 5 security level). A three-phase protocol — Pending (encapsulation), Exchange (via blind relay), Commit (atomic promotion) — replaces `RootState_curr` with fresh PQ-derived material. Auto-commit detection on the decrypt path ensures both peers converge without an extra round-trip.

### 4. Constant-Flow Cover Traffic

A background timer fires every 5 seconds. If a real message is queued, it is sent. Otherwise, a 4096-byte packet filled with OsRng white noise is transmitted. All packets are exactly 4096 bytes. To any network observer, every peer at every moment is sending identical-sized indistinguishable packets — the social graph is cryptographically hidden.

### 5. Zero Server Architecture

No key directory. No pre-key server. No message queue. No identity server. The only network dependency is TDLib as a blind relay — it sees ciphertext but cannot decrypt, authenticate, or correlate sessions.

---

## Theoretical Foundation

SecureCore's key evolution and self-healing mechanism is formally analyzed in the accompanying research paper:

**[Post-Compromise Security Without External Entropy](docs/paper.pdf)** — *eprint.iacr.org, 2026*

The paper proves that a PRP-based state evolution achieves **tight post-compromise security with zero external entropy**. It shows that the unidirectional self-healing LinkChat implements via `commit_evolution` / `decrypt_with_auto_commit` is theoretically optimal: the adversary's advantage is bounded between τ/2^{λ+1} and τ/2^{λ}, where τ is the number of healing steps and λ is the security parameter. No external entropy source is required beyond the initial root key.

*Anonymous. Priority established via IACR eprint timestamp.*

---

## Architecture

```
┌──────────────────────────────────────────────────────────┐
│  Swift / Kotlin (iOS / Android)                          │
│  Calls C ABI functions with (*const u8, u32) only        │
├──────────────────────────────────────────────────────────┤
│  lib.rs                    22 extern "C" FFI functions   │
├──────────────┬──────────────┬────────────────────────────┤
│ root_state   │ init_module  │ message_cipher             │
│ 3 globals    │ USB-C init   │ AES-256-GCM + HKDF-Expand  │
│ commit/roll  │ ID_Stamp     │ auto-commit PCS            │
├──────────────┼──────────────┼────────────────────────────┤
│ evolution    │ anti_dos     │ constant_flow              │
│ ML-KEM-1024  │ epoch roll   │ 5s timer + 4KB packets     │
│ 3-phase      │ 100k cap     │ white noise fill           │
├──────────────┼──────────────┼────────────────────────────┤
│ tail_padding │ virtual_volume│ memory_protection         │
│ [16,512]B    │ ChaCha20 AEAD │ SecureBuffer + panic exit │
│ OsRng noise  │ per-block key│ zeroize-on-drop            │
├──────────────┴──────────────┼────────────────────────────┤
│ disk_wipe                   │ clock_align                │
│ 2-pass + truncate           │ median skew estimator      │
└─────────────────────────────┴────────────────────────────┘
```

**Module dependency graph:**
```
lib.rs ──► all modules (FFI boundary only)
root_state ──► (standalone + hkdf + sha2)
message_cipher ──► root_state + aes_gcm + hkdf
init_module ──► root_state + sha2 + lib.rs(vault helpers)
evolution ──► root_state + memory_protection + pqc_kyber
anti_dos ──► root_state
constant_flow ──► (standalone + rand)
virtual_volume ──► (standalone + chacha20poly1305 + hmac)
```

---

## Module Overview

| Module | File | Purpose | Key Types/Functions |
|--------|------|---------|---------------------|
| **FFI Bridge** | [`lib.rs`](secure_core/src/lib.rs) | All 22 `extern "C"` entry points, heap allocator, vault singleton | `init_virtual_volume`, `encrypt_message`, `decrypt_with_auto_commit`, `start_evolution` |
| **Root State** | [`root_state.rs`](secure_core/src/root_state.rs) | 3 global variables protected by `OnceLock<Mutex<>>` | `ROOT_STATE_CURR`, `ROOT_STATE_PEND`, `EPOCH_ID` |
| **Initialization** | [`init_module.rs`](secure_core/src/init_module.rs) | Offline USB-C entropy interleave, ID_Stamp derivation, entropy quality check | `initialise_root_state`, `compute_id_stamp` |
| **Message Cipher** | [`message_cipher.rs`](secure_core/src/message_cipher.rs) | AES-256-GCM encrypt/decrypt, HKDF key derivation, auto-commit PCS | `derive_message_key`, `encrypt`, `try_decrypt_with_evolution` |
| **Evolution** | [`evolution.rs`](secure_core/src/evolution.rs) | ML-KEM-1024 three-phase post-quantum key rotation with MITM detection | `start_evolution`, `apply_peer_kem`, `commit_evolution` |
| **Anti-DoS** | [`anti_dos.rs`](secure_core/src/anti_dos.rs) | Epoch-based roll-forward recovery after packet loss | `recover_after_loss` |
| **Constant Flow** | [`constant_flow.rs`](secure_core/src/constant_flow.rs) | 5-second rigid timer, 4KB fixed-size packets, TRNG fill | `start_constant_flow`, `build_noise_packet` |
| **Tail Padding** | [`tail_padding.rs`](secure_core/src/tail_padding.rs) | Append [16,512] bytes OsRng noise + 2B length trailer | `add_tail_padding`, `strip_tail_padding` |
| **Virtual Volume** | [`virtual_volume.rs`](secure_core/src/virtual_volume.rs) | Single-file AES-encrypted vault (`vault.sec`), per-block ChaCha20Poly1305, bitmap allocator, canary honeytraps | 4096B blocks, 262,144 max data blocks, ~1 GiB usable |
| **Memory Protection** | [`memory_protection.rs`](secure_core/src/memory_protection.rs) | `SecureBuffer` (zeroize-on-drop), `execute_panic_exit` (SIGTERM + 3ms + `_exit(1)`) | `SecureBuffer`, `execute_panic_exit` |
| **Disk Wipe** | [`disk_wipe.rs`](secure_core/src/disk_wipe.rs) | Multi-pass secure vault destruction: OsRng random → zeros → truncate → fsync | `purge_entire_vault` |
| **Clock Align** | [`clock_align.rs`](secure_core/src/clock_align.rs) | Adaptive clock-skew estimator using 16-slot ring buffer of counter deltas | `init_clock_align`, `estimated_skew` |

---

## Cryptographic Primitives

| Algorithm | Crate | Key Size | Mode / Construction | Usage |
|-----------|-------|----------|---------------------|-------|
| **AES-256-GCM** | `aes_gcm` | 256-bit | GCM (12B nonce, 16B tag) | Message encryption |
| **ChaCha20Poly1305** | `chacha20poly1305` | 256-bit | AEAD (12B nonce, 16B tag per write) | Vault block storage |
| **ML-KEM-1024** | `pqc_kyber` | SK 3168B, PK 1568B, SS 32B | KEM (Encaps/Decaps) | Post-quantum key evolution |
| **HKDF-SHA256** | `hkdf` + `sha2` | 256-bit IKM/OKM | Extract-then-Expand (RFC 5869) | Message key derivation, evolution, roll |
| **HMAC-SHA256** | `hmac` + `sha2` | 256-bit key | MAC (used as KDF) | Vault per-block key derivation |
| **SHA-256** | `sha2` | — | Hash | ID_Stamp, RootState init, PK binding |
| **OsRng** | `rand::rngs::OsRng` | — | OS CSPRNG | All nonces, padding, noise, wipe passes |

### Domain Separation Strings

| String | Salt/Info | Module | Context |
|--------|-----------|--------|---------|
| `"LinkChat HKDF Expand"` | HKDF salt | `message_cipher` | Message key derivation |
| `"LinkChat Evolution"` | HKDF info | `evolution` | Pending key derivation |
| `"LinkChat RootState Init"` | Hash prefix | `init_module` | RootState from interleaved entropy |
| `"LinkChat ID Stamp"` | Hash prefix | `init_module` | Identity stamp (binds RootState + Bob PK) |
| `"LinkChat Epoch Roll"` | HKDF info | `anti_dos` | Epoch roll-forward |
| `"epoch_roll"` | HKDF salt | `anti_dos` | Epoch roll-forward |
| `"blk_key_v1"` | HMAC message | `virtual_volume` | Per-block key derivation |

---

## Key Lifecycle

### Birth — Offline Initialization
```
1. Bob generates ML-KEM-1024 keypair (pk: 1568B, sk: 3168B)
2. Alice + Bob physically connect (USB-C + BLE)
3. Bob sends: entropy_bytes + public_key
4. init_root_state(alice_entropy, bob_entropy, bob_pk)
   → entropy quality check (reject all-zero / all-same / < 64B)
   → odd_even_interleave(alice, bob)
   → SHA-256("LinkChat RootState Init" || interleaved)
   → ROOT_STATE_CURR[32], EPOCH_ID = 0
5. generate_id_stamp()
   → SHA-256("LinkChat ID Stamp" || RootState_init || bob_pk)
   → written to vault block 994
   → ALL future messages bind to this session via id_stamp in AAD
```

### Use — Per-Message Encryption
```
msg_seq = atomic_fetch_add(MSG_COUNTER, 1)   // never 0
Message_Key = HKDF-Expand(
    salt = "LinkChat HKDF Expand",
    ikm  = ROOT_STATE_CURR,
    info = [epoch(4B LE) || msg_seq(8B LE)]
)  → 32 bytes

nonce = [epoch(4B) || (timestamp ^ msg_seq)(8B)]  → 12 bytes, deterministic

AAD = [
    id_stamp(32B)    || direction(1B: 0=out/1=in) ||
    epoch(4B LE)     || msg_seq(8B LE) ||
    timestamp(8B LE) || proto_version(2B LE = 4)
]  → 55 bytes total

Wire format: [12B nonce || AES-256-GCM ciphertext || 16B GCM tag]
Then:      add_tail_padding(wire) → [wire || noise_L || u16_le(L)]
Then:      constant_flow → padded to exactly 4096 bytes
```

### Rotate — Post-Quantum Evolution (PCS)
```
Phase 1 (Alice):
  start_evolution()
    → pqc_kyber::encapsulate(bob_pk, &mut OsRng)
    → (kem_ct: 1568B, shared_secret_S: 32B)
    → RootState_pend = HKDF-Extract(salt=S, ikm=RootState_curr)
    → stored in global, kem_ct sent to Bob via TDLib

Phase 2 (Bob):
  apply_peer_kem(kem_ct)
    → pqc_kyber::decapsulate(kem_ct, sk)
    → same shared_secret_S: 32B
    → same RootState_pend derivation
    → Bob commits → sends reply with new epoch

Phase 3 (Alice):
  decrypt_with_auto_commit(reply)
    → decryption with RootState_curr fails
    → tries RootState_pend → success
    → auto-commit: RootState_curr ← RootState_pend, epoch++, msg_counter=1
```

### Recover — Anti-DoS Epoch Roll
```
recover_after_loss(target_epoch)
  for each missed epoch:
    RootState_curr = HKDF-Extract(salt="epoch_roll", ikm=RootState_curr)
    epoch += 1
  Maximum gap: 100,000 epochs per call
```

---

## Wire Formats

### Encrypted Message
```
[12B: nonce (epoch||timestamp^msg_seq)] [N B: AES-256-GCM ct] [16B: GCM tag]
Minimum: 28 bytes
```

### After Tail Padding
```
[encrypted message] [L B: OsRng noise, 16≤L≤512] [2B: u16 LE L]
```

### Constant-Flow Packet
```
Exactly 4096 bytes (real message padded with OsRng, or pure noise)
```

### Vault Block (4096 bytes on disk)
```
[12B: random ChaCha20Poly1305 nonce] [4084B: encrypted payload + 16B tag]
PAYLOAD_SIZE = 4068 bytes of plaintext per block
```

### Vault Superblock (Block 0)
```
u32 LE magic = 0x5345_4333 ("SEC3")
u32 LE version = 3
u64 LE total_blocks
u64 LE free_blocks
[u8; 32] master_key_hash = SHA-256(master_key)
[u8; 4040] reserved (zeros)
```

### Canary Honeytrap (Blocks 995–999)
```
"CANARY"(6B) | slot_index(1B) | version=0x01(1B) | OsRng padding(4060B)
```

### KEM Ciphertext
```
ML-KEM-1024 encaps output: 1568 bytes
Shared secret: 32 bytes
```

---

## FFI Reference

All 22 `extern "C"` functions. Every data pointer is `*const u8` or `*mut u8`. Every length is `u32`. Memory returned to caller must be freed via `release_native_buffer`.

### Vault I/O
| Function | Signature | Returns |
|----------|-----------|---------|
| `init_virtual_volume` | `(path, path_len, key, key_len, total) → u32` | 0=ok, 1/2/3=error |
| `read_vault_blocks` | `(start, n, out) → u32` | blocks read |
| `write_vault_blocks` | `(start, n, data) → u32` | blocks written |
| `allocate_vault_block` | `() → u64` | block index or u64::MAX |
| `free_vault_block` | `(idx) → u32` | 0=ok |
| `secure_erase_block` | `(idx) → u32` | 0=ok |
| `vault_total_blocks` | `() → u64` | count |
| `vault_free_blocks` | `() → u64` | count |
| `validate_canary_slots` | `() → u32` | 0=intact, 2=tampered |
| `init_canary_slots` | `() → u32` | 0=ok |
| `purge_vault` | `(path, path_len) → u32` | never returns on success |

### Root State & Identity
| Function | Signature | Returns |
|----------|-----------|---------|
| `init_root_state` | `(a, a_len, b, b_len, pk, pk_len) → u32` | 0=ok, 1/2/3=error |
| `get_epoch_id` | `() → u32` | current epoch |
| `generate_id_stamp` | `() → u32` | 0=ok |
| `load_id_stamp` | `(out, out_cap) → u32` | 0=ok |

### Message Encrypt/Decrypt
| Function | Signature | Returns |
|----------|-----------|---------|
| `msg_counter_next` | `() → u64` | sequence number |
| `msg_counter_current` | `() → u64` | sequence number |
| `derive_message_key` | `(epoch, msg_seq) → *mut u8` | 32B heap key |
| `encrypt_message` | `(pt, pt_len, key, stamp, outgoing, epoch, msg_seq, timestamp, out_len) → *mut u8` | ciphertext or null |
| `decrypt_message` | `(ct, ct_len, key, stamp, outgoing, epoch, msg_seq, timestamp, out_len) → *mut u8` | plaintext or null |
| `decrypt_with_auto_commit` | `(... , did_commit) → *mut u8` | plaintext + auto-commit flag |
| `zeroize_key` | `(ptr, len) → u32` | 0 |
| `add_tail_padding` | `(data, data_len, out_len) → *mut u8` | padded or null |
| `strip_tail_padding` | `(data, data_len, out_len) → *mut u8` | payload or null |

### Post-Quantum Evolution
| Function | Signature | Returns |
|----------|-----------|---------|
| `evolution_generate_bob_keypair` | `(pk, pk_cap, sk, sk_cap) → u32` | 0=ok |
| `evolution_set_peer_public_key` | `(pk, pk_len) → u32` | 0=ok |
| `start_evolution` | `() → u32` | 0=ok, 1/2/4/5=error |
| `kem_cipher_len` | `() → u32` | byte count |
| `get_kem_cipher` | `(out, cap) → u32` | bytes written |
| `apply_peer_kem` | `(ct, ct_len) → u32` | 0=ok, 2/3/4=error |
| `commit_evolution` | `() → u32` | 0=ok, 1=no pending |

### Cover Traffic & Recovery
| Function | Signature | Returns |
|----------|-----------|---------|
| `build_noise_packet` | `(out, out_len) → u32` | 0=ok |
| `start_constant_flow` | `(cb: TxCallback) → u32` | 0=ok, 1=already-running |
| `stop_constant_flow` | `() → u32` | 0 |
| `recover_after_loss` | `(target_epoch) → u32` | new epoch or u32::MAX |
| `init_clock_align` | `()` | void |
| `estimated_clock_skew` | `() → i64` | counter steps |

### Heap
| Function | Signature | Returns |
|----------|-----------|---------|
| `allocate_native_buffer` | `(size) → *mut u8` | heap pointer or null |
| `release_native_buffer` | `(ptr, len)` | void (zeroize + free) |

---

## Error Codes

| Code | Meaning |
|------|---------|
| **0** | Success |
| **1** | Null pointer / zero-length input / insufficient data / no pending key / general error |
| **2** | Invalid UTF-8 path / canary tampered / empty peer public key / entropy quality rejected |
| **3** | Vault I/O error / Bob secret key not found |
| **4** | Shared secret length mismatch (not exactly 32B from ML-KEM-1024) |
| **5** | Public key tampered — SHA-256 hash mismatch (MITM detection) |
| **u64::MAX** | Vault allocation failed |
| **u32::MAX** | HKDF failure or epoch gap > 100,000 |

---

## Build & Integrate

### Prerequisites
- Rust 1.70+
- `cargo`

### Build
```bash
cd secure_core
cargo build --release
# Output:
#   target/release/libsecure_core.a   — static library (iOS/macOS)
#   target/release/libsecure_core.so  — dynamic library (Android/Linux)
```

### Test
```bash
cargo test
# 21 tests: roundtrip encrypt/decrypt, evolution cycle, vault block I/O,
#           tail padding, anti-DoS recovery, memory protection, clock align
```

### Integrate with iOS (Swift)
Link `libsecure_core.a` into your Xcode project. All functions are `extern "C"` with raw pointers. The Swift bridge (`NativeBridge.swift`) wraps each FFI call with `Array.withUnsafeBytes` / `UnsafeMutablePointer` conversions.

---

## Security Properties

| Property | Status | Mechanism |
|----------|--------|-----------|
| Message confidentiality | ✅ | AES-256-GCM per-message AEAD |
| Per-message key independence | ✅ | HKDF-Expand from RootState with unique `(epoch, msg_seq)` |
| Cross-epoch forward secrecy | ✅ | ML-KEM-1024 three-phase key evolution |
| Post-compromise security | ✅ | Auto-commit on decrypt detects peer's new epoch |
| Ciphertext authentication | ✅ | GCM 16B tag + AAD binding (id_stamp, direction, epoch, seq, timestamp, protocol version) |
| Anti-replay | ⚠️ | Unique `msg_seq` per epoch; caller must track `max_seq_seen` |
| Post-quantum | ✅ | ML-KEM-1024 for all key rotation (Category 5) |
| Traffic analysis resistance | ✅ | 5s constant-flow, 4KB fixed packets, white-noise fill |
| Local storage encryption | ✅ | ChaCha20Poly1305 per-block AEAD vault |
| Deniability | ✅ | Symmetric keys only (no signatures) + one-click vault purge |
| Metadata protection | ✅ | `freeze_timestamps()` after every vault I/O |
| Tamper detection | ✅ | Canary honeytrap blocks (995–999) + AEAD on all data blocks |
| Memory safety | ✅ | `SecureBuffer` zeroize-on-drop, key copies zeroized after use |
| Server trust | ✅ | Zero server architecture — TDLib is blind relay only |

### What Is NOT Protected
- Compromised device (jailbreak / root)
- Telegram metadata (TDLib sees timing, IP, message size)
- Screenshots / manual forwarding by recipient
- Social engineering / SAS oral verification failure
- Unencrypted iTunes/Finder backups containing `vault.sec`
- Physical coercion (deniable encryption mitigates but does not eliminate)

---

## Comparison to Signal Protocol

| Property | Signal Protocol | SecureCore  |
|----------|----------------|---------------|
| Initial key exchange | X3DH over network | USB-C + BLE physical interleave |
| Per-message PCS | DH Ratchet (automatic) | Epoch-level (explicit trigger) |
| PCS healing time | 1–2 round-trips | 1 KEM round-trip |
| Post-quantum | PQXDH (initial exchange only) | Full ML-KEM-1024 (all rotations) |
| Metadata protection | None | Constant-flow cover traffic |
| Server dependency | Mandatory (pre-key server) | None (TDLib blind relay) |
| Identity | Asymmetric Curve25519 | Symmetric ID_Stamp (SHA-256) |
| Async messaging | Yes (pre-key bundles) | No (synchronous only) |

For a detailed analysis, see [`SIGNAL_COMPARISON.md`](SIGNAL_COMPARISON.md) (if present in the repo).

---

## Known Limitations

1. **No per-message DH ratchet.** Epoch-level PCS requires explicit ML-KEM evolution for healing.
2. **No asynchronous messaging.** Both peers must be online for initialization and evolution commit.
3. **No multi-device support.** ID_Stamp binds to a single pairing session.
4. **No PBKDF2/Argon2 for vault master key.** The 32-byte key is used directly.
5. **Message sequence counter is in-memory only.** Resets to 1 on process restart.
6. **Single vault singleton.** Only one `vault.sec` can be open at a time.
7. **No network I/O in Rust.** All transport is delegated to Swift/Kotlin via callback.
8. **Disk wipe is cryptographic, not physical.** APFS/SSD wear-leveling prevents guaranteed physical overwrite.
9. **`register_touch` is a stub.** GUI touch tracking is not implemented.
10. **Clock align forward-seek is documented but not implemented.**

---

## License

MIT
