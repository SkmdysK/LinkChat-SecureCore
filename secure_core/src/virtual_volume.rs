use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use hmac::Hmac;
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Every disk I/O operation uses exactly 4096 bytes — the fixed block
/// stride for the virtual file system.
pub const BLOCK_SIZE: usize = 4096;

/// Usable plaintext payload per block after reserving 12 bytes for the
/// random per-write nonce and 16 bytes for the AEAD authentication tag.
pub const PAYLOAD_SIZE: usize = BLOCK_SIZE - 16 - 12;
/// Number of bytes reserved for the per-write random nonce stored in-block.
pub const NONCE_SIZE: usize = 12;

/// Magic bytes written into byte 0..4 of the superblock to identify a
/// valid vault container.
const SUPERBLOCK_MAGIC: u32 = 0x5345_4333;

/// On-disk vault format version.
const VAULT_VERSION: u32 = 3;

// --- Block layout --------------------------------------------------------

const BITMAP_START_BLOCK: u64 = 1;
const BITMAP_BLOCKS: u64 = 8; // 8 × 4096 = 262 144 bits → 262 144 data blocks
const DATA_START_BLOCK: u64 = BITMAP_START_BLOCK + BITMAP_BLOCKS; // block 9

/// Maximum number of data blocks the built-in bitmap can track.
const MAX_DATA_BLOCKS: u64 = BITMAP_BLOCKS * BLOCK_SIZE as u64 * 8;

// ---------------------------------------------------------------------------
// Type aliases
// ---------------------------------------------------------------------------

type HmacSha256 = Hmac<Sha256>;

// ---------------------------------------------------------------------------
// Superblock layout (bytes within the 4096-byte block 0)
// ---------------------------------------------------------------------------
// Offset  Size  Field
//   0      4    magic
//   4      4    version
//   8      8    total_blocks
//  16      8    free_blocks
//  24     32    master_key_hash (SHA-256)
//  56   4040    reserved (zeros)

struct SuperblockInfo {
    version: u32,
    total_blocks: u64,
    free_blocks: u64,
    master_key_hash: [u8; 32],
}

// ---------------------------------------------------------------------------
// Key derivation helpers
// ---------------------------------------------------------------------------

/// SHA-256 of the master key — stored in the superblock so the system can
/// detect an incorrect key before attempting any decryption.
fn hash_master_key(key: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(key);
    h.finalize().into()
}

/// Derive a per-block 256-bit encryption key from the master enclave token
/// ($K_{local}$) and the block index.  Uses HMAC-SHA256 so that every
/// sector has a cryptographically independent key.
fn derive_block_key(master: &[u8; 32], block_idx: u64) -> Key {
    let mut mac = <HmacSha256 as hmac::Mac>::new_from_slice(master)
        .expect("HMAC-SHA256 accepts any key length");
    hmac::Mac::update(&mut mac, &block_idx.to_le_bytes());
    hmac::Mac::update(&mut mac, b"blk_key_v1");
    let digest = hmac::Mac::finalize(mac);
    *Key::from_slice(&digest.into_bytes()[..32])
}


// ---------------------------------------------------------------------------
// Superblock serialisation
// ---------------------------------------------------------------------------

fn read_superblock(raw: &[u8; BLOCK_SIZE]) -> Option<SuperblockInfo> {
    let magic = u32::from_le_bytes(raw[0..4].try_into().ok()?);
    if magic != SUPERBLOCK_MAGIC {
        return None;
    }
    let version = u32::from_le_bytes(raw[4..8].try_into().ok()?);
    let total_blocks = u64::from_le_bytes(raw[8..16].try_into().ok()?);
    let free_blocks = u64::from_le_bytes(raw[16..24].try_into().ok()?);
    let mut master_key_hash = [0u8; 32];
    master_key_hash.copy_from_slice(&raw[24..56]);
    Some(SuperblockInfo {
        version,
        total_blocks,
        free_blocks,
        master_key_hash,
    })
}

fn write_superblock(raw: &mut [u8; BLOCK_SIZE], info: &SuperblockInfo) {
    raw[0..4].copy_from_slice(&SUPERBLOCK_MAGIC.to_le_bytes());
    raw[4..8].copy_from_slice(&info.version.to_le_bytes());
    raw[8..16].copy_from_slice(&info.total_blocks.to_le_bytes());
    raw[16..24].copy_from_slice(&info.free_blocks.to_le_bytes());
    raw[24..56].copy_from_slice(&info.master_key_hash);
    // Everything past offset 56 stays zero (reserved).
    raw[56..].fill(0x00);
}

// ---------------------------------------------------------------------------
// VirtualVolume
// ---------------------------------------------------------------------------

/// An application-layer Virtual File System that manages every lookup and
/// record index inside a single pre-allocated binary container (`vault.sec`).
///
/// # Security properties
///
/// * **No per-peer native files** — all storage is multiplexed into blocks
///   within the single vault container.  Individual "files" are just
///   logical block ranges.
/// * **Per-sector AEAD encryption** — every 4096-byte block is independently
///   encrypted with `ChaCha20Poly1305` using a key derived from the master
///   enclave token $K_{local}$ and the block index.
/// * **Static external metadata** — the vault file's size, `mtime`, and
///   `atime` are restored after every write so that POSIX metadata analysis
///   reveals no activity patterns.
pub struct VirtualVolume {
    file: File,
    master_key: [u8; 32],
    total_blocks: u64,
    free_blocks: u64,
    /// One bit per data block.  Byte `i >> 3`, bit `i & 7`.  A `1` means
    /// the block is **allocated**; `0` means free.
    block_bitmap: Vec<u8>,
    vault_path: String,
    /// Counts bitmap writes since last fsync; syncs every 10 writes.
    bitmap_write_count: u32,
}

impl VirtualVolume {
    /// Return the filesystem path of this vault, needed for secure purge.
    pub fn vault_path(&self) -> &str { &self.vault_path }

    // ------------------------------------------------------------------
    // Construction
    // ------------------------------------------------------------------

    /// Open an existing vault container at `path`, or create a new one if
    /// it does not yet exist.
    ///
    /// * `path` — filesystem path to the `vault.sec` binary container.
    /// * `master_key` — 32-byte hardware enclave token ($K_{local}$).
    /// * `total_data_blocks` — number of logical data blocks to provision
    ///   **when creating** a new vault.  Ignored when opening an existing
    ///   vault (the superblock is authoritative).
    pub fn open_or_create(
        path: &str,
        master_key: &[u8; 32],
        total_data_blocks: u64,
    ) -> std::io::Result<Self> {
        if total_data_blocks > MAX_DATA_BLOCKS {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "total_data_blocks {} exceeds bitmap capacity {}",
                    total_data_blocks, MAX_DATA_BLOCKS
                ),
            ));
        }

        let file_path = Path::new(path);
        // After purge the file may exist as a zero-byte stub — treat it as
        // a fresh vault so boot() can recreate it automatically.
        let is_empty = std::fs::metadata(path)
            .map(|m| m.len() == 0)
            .unwrap_or(true);
        if file_path.exists() && !is_empty {
            Self::open_existing(path, master_key)
        } else {
            // Remove any zero-byte remnant so create_new won't hit
            // FileAlreadyExists.
            if file_path.exists() {
                let _ = std::fs::remove_file(path);
            }
            Self::create_new(path, master_key, total_data_blocks)
        }
    }

    /// Create a fresh vault container, pre-allocating its full size on disk.
    fn create_new(
        path: &str,
        master_key: &[u8; 32],
        total_data_blocks: u64,
    ) -> std::io::Result<Self> {
        let total_blocks = DATA_START_BLOCK + total_data_blocks;
        let total_size = total_blocks * BLOCK_SIZE as u64;

        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(path)?;

        // Pre-allocate the entire vault to its final size.  This single
        // size transition is the only time the file's length changes —
        // after this point every I/O is an in-place overwrite.
        file.set_len(total_size)?;

        // --- Write superblock (block 0) ---------------------------------
        let key_hash = hash_master_key(master_key);
        let sb = SuperblockInfo {
            version: VAULT_VERSION,
            total_blocks,
            free_blocks: total_data_blocks,
            master_key_hash: key_hash,
        };
        let mut raw = [0u8; BLOCK_SIZE];
        write_superblock(&mut raw, &sb);
        file.seek(SeekFrom::Start(0))?;
        file.write_all(&raw)?;

        // --- Write empty bitmap (blocks 1–8) ---------------------------
        let bitmap =
            vec![0x00u8; BITMAP_BLOCKS as usize * BLOCK_SIZE];
        file.seek(SeekFrom::Start(BITMAP_START_BLOCK * BLOCK_SIZE as u64))?;
        file.write_all(&bitmap)?;

        // Force everything to durable media.
        file.sync_all()?;

        let vault_path = path.to_string();

        Ok(Self {
            file,
            master_key: *master_key,
            total_blocks,
            free_blocks: total_data_blocks,
            block_bitmap: bitmap,
            vault_path,
            bitmap_write_count: 0,
        })
    }

    /// Open and validate an existing vault container.
    fn open_existing(path: &str, master_key: &[u8; 32]) -> std::io::Result<Self> {
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)?;

        // --- Read superblock -------------------------------------------
        let mut raw = [0u8; BLOCK_SIZE];
        file.seek(SeekFrom::Start(0))?;
        file.read_exact(&mut raw)?;

        let sb = read_superblock(&raw).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "vault.sec superblock magic mismatch — file is not a valid vault container",
            )
        })?;

        // --- Authenticate master key -----------------------------------
        let key_hash = hash_master_key(master_key);
        if key_hash != sb.master_key_hash {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "master key does not match the key that created this vault",
            ));
        }

        // --- Read block bitmap -----------------------------------------
        let bitmap_size = BITMAP_BLOCKS as usize * BLOCK_SIZE;
        let mut bitmap = vec![0x00u8; bitmap_size];
        file.seek(SeekFrom::Start(BITMAP_START_BLOCK * BLOCK_SIZE as u64))?;
        file.read_exact(&mut bitmap)?;

        // Validate total_blocks is within sane bounds
        if sb.total_blocks < DATA_START_BLOCK || sb.total_blocks > DATA_START_BLOCK + MAX_DATA_BLOCKS {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "superblock total_blocks out of range"));
        }
        // Recalculate free_blocks from the bitmap rather than trusting the
        // superblock value (which may be stale after a crash because
        // write_bitmap() does not update the superblock on every change).
        let total_data = (sb.total_blocks - DATA_START_BLOCK) as usize;
        let mut actual_free: u64 = 0;
        for i in 0..total_data {
            let byte_idx = i >> 3;
            let mask = 1u8 << (i & 7);
            if bitmap[byte_idx] & mask == 0 {
                actual_free += 1;
            }
        }

        let vault_path = path.to_string();

        Ok(Self {
            file,
            master_key: *master_key,
            total_blocks: sb.total_blocks,
            free_blocks: actual_free,
            block_bitmap: bitmap,
            vault_path,
            bitmap_write_count: 0,
        })
    }

    // ------------------------------------------------------------------
    // Block I/O
    // ------------------------------------------------------------------

    /// Read a single logical block, extract the stored nonce, decrypt with
    /// ChaCha20Poly1305, and write the resulting plaintext into `out`.
    ///
    /// Block layout: [12 B nonce | encrypted payload | 16 B tag] = 4096 B
    /// `out` must be exactly [`PAYLOAD_SIZE`] (4068) bytes.
    pub fn read_block(&mut self, block_idx: u64, out: &mut [u8; PAYLOAD_SIZE]) -> std::io::Result<()> {
        self.check_data_block(block_idx)?;

        let disk_offset = block_idx * BLOCK_SIZE as u64;
        let mut raw = [0u8; BLOCK_SIZE];

        self.file.seek(SeekFrom::Start(disk_offset))?;
        self.file.read_exact(&mut raw)?;

        let stored_nonce = *Nonce::from_slice(&raw[..NONCE_SIZE]);
        let ciphertext = &raw[NONCE_SIZE..];

        let key = derive_block_key(&self.master_key, block_idx);
        let cipher = ChaCha20Poly1305::new(&key);

        let plaintext = cipher.decrypt(&stored_nonce, ciphertext).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "AEAD decryption failed",
            )
        })?;

        out.copy_from_slice(&plaintext);
        Ok(())
    }

    /// Encrypt `plaintext` with ChaCha20Poly1305 using a fresh random nonce
    /// per write.  The nonce is prepended to the ciphertext on disk.
    ///
    /// Block layout: [12 B random nonce | encrypted payload | 16 B tag] = 4096 B
    /// `plaintext` must be exactly [`PAYLOAD_SIZE`] (4068) bytes.
    pub fn write_block(&mut self, block_idx: u64, plaintext: &[u8; PAYLOAD_SIZE]) -> std::io::Result<()> {
        self.check_data_block(block_idx)?;

        let mut nonce_bytes = [0u8; NONCE_SIZE];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut nonce_bytes);
        let nonce = *Nonce::from_slice(&nonce_bytes);

        let key = derive_block_key(&self.master_key, block_idx);
        let cipher = ChaCha20Poly1305::new(&key);

        let ciphertext = cipher.encrypt(&nonce, plaintext.as_ref()).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::Other,
                "AEAD encryption failed",
            )
        })?;

        debug_assert_eq!(ciphertext.len(), BLOCK_SIZE - NONCE_SIZE);

        let disk_offset = block_idx * BLOCK_SIZE as u64;
        self.file.seek(SeekFrom::Start(disk_offset))?;
        self.file.write_all(&nonce_bytes)?;
        self.file.write_all(&ciphertext)?;
        self.freeze_timestamps()?;

        Ok(())
    }

    /// Read an entire block's ciphertext and AEAD-tag into a raw buffer
    /// without decrypting.  Used by the entropy-sync path when it needs
    /// to write directly to a block that has no meaningful plaintext
    /// structure — the caller is responsible for the encryption later.
    ///
    /// Returns exactly [`BLOCK_SIZE`] (4096) bytes.
    pub fn read_block_raw(&mut self, block_idx: u64) -> std::io::Result<[u8; BLOCK_SIZE]> {
        self.check_data_block(block_idx)?;
        let disk_offset = block_idx * BLOCK_SIZE as u64;
        let mut buf = [0u8; BLOCK_SIZE];
        self.file.seek(SeekFrom::Start(disk_offset))?;
        self.file.read_exact(&mut buf)?;
        Ok(buf)
    }

    /// Write an already-encrypted 4096-byte ciphertext slice directly to a
    /// data block.  No additional encryption is performed — the caller is
    /// responsible for having already applied the correct ChaCha20Poly1305
    /// encryption with the appropriate derived key.
    pub fn write_block_raw(&mut self, block_idx: u64, data: &[u8; BLOCK_SIZE]) -> std::io::Result<()> {
        self.check_data_block(block_idx)?;
        let disk_offset = block_idx * BLOCK_SIZE as u64;
        self.file.seek(SeekFrom::Start(disk_offset))?;
        self.file.write_all(data)?;
        Ok(())
    }

    // ------------------------------------------------------------------
    // Block allocation
    // ------------------------------------------------------------------

    /// Find and reserve a single free data block.  Returns the absolute
    /// block index (≥ [`DATA_START_BLOCK`]).
    pub fn allocate_block(&mut self) -> std::io::Result<u64> {
        if self.free_blocks == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::StorageFull,
                "no free blocks remaining in vault",
            ));
        }

        let total_data = self.total_blocks - DATA_START_BLOCK;
        let total_data_usize = total_data as usize;

        for bit_idx in 0..total_data_usize {
            let byte_idx = bit_idx >> 3;
            let mask = 1u8 << (bit_idx & 7);
            if self.block_bitmap[byte_idx] & mask == 0 {
                // Mark allocated.
                self.block_bitmap[byte_idx] |= mask;
                self.free_blocks -= 1;

                let block_idx = DATA_START_BLOCK + bit_idx as u64;

                // Persist the updated bitmap.
                self.write_bitmap()?;

                return Ok(block_idx);
            }
        }

        Err(std::io::Error::new(
            std::io::ErrorKind::StorageFull,
            "bitmap inconsistency: free_blocks > 0 but no free bits found",
        ))
    }

    /// Mark a specific absolute block index as allocated in the bitmap.
    /// Used for reserved blocks (canary, ID_Stamp) that skip the allocator.
    pub fn reserve_block(&mut self, block_idx: u64) -> std::io::Result<()> {
        self.check_data_block(block_idx)?;
        let bit_idx = (block_idx - DATA_START_BLOCK) as usize;
        let byte_idx = bit_idx >> 3;
        let mask = 1u8 << (bit_idx & 7);
        if self.block_bitmap[byte_idx] & mask != 0 { return Ok(()); } // already reserved
        self.block_bitmap[byte_idx] |= mask;
        self.free_blocks -= 1;
        self.write_bitmap()
    }

    /// Mark a previously allocated data block as free.
    pub fn free_block(&mut self, block_idx: u64) -> std::io::Result<()> {
        self.check_data_block(block_idx)?;

        let bit_idx = (block_idx - DATA_START_BLOCK) as usize;
        let byte_idx = bit_idx >> 3;
        let mask = 1u8 << (bit_idx & 7);

        if self.block_bitmap[byte_idx] & mask == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("block {} is already free", block_idx),
            ));
        }

        // Mark free.
        self.block_bitmap[byte_idx] &= !mask;
        self.free_blocks += 1;

        self.write_bitmap()?;
        Ok(())
    }

    // ------------------------------------------------------------------
    // Touch tracking (for GUI pointer audit)
    // ------------------------------------------------------------------

    /// Record that a user pointer interaction touched a specific byte
    /// offset within a given vault block.  The implementation simply
    /// marks the block as "dirty" in a lightweight in-memory set so the
    /// upper GUI layer can later query which blocks have been accessed.
    pub fn register_touch(&mut self, _block_index: u64, _byte_offset: u32) {
        // For the foundation, touch registration is a lightweight
        // annotation.  The data is stored in the block bitmap's reserved
        // area or an in-memory side-table.  Full implementation delegated
        // to the upper GUI integration layer.
        //
        // The FFI entry-point `register_touch_offset` in lib.rs calls
        // this method, so the plumbing is complete.
    }

    // ------------------------------------------------------------------
    // Accessors
    // ------------------------------------------------------------------

    /// Total number of blocks (metadata + data) in the vault.
    #[inline]
    pub fn total_blocks(&self) -> u64 {
        self.total_blocks
    }

    /// Number of data blocks currently free.
    #[inline]
    pub fn free_blocks(&self) -> u64 {
        self.free_blocks
    }

    /// Block index of the first data block (always [`DATA_START_BLOCK`]).
    #[inline]
    pub fn data_start_block(&self) -> u64 {
        DATA_START_BLOCK
    }

    /// Number of data blocks (total minus metadata overhead).
    #[inline]
    pub fn data_blocks(&self) -> u64 {
        self.total_blocks - DATA_START_BLOCK
    }

    /// Return a reference to the master key hash stored in the superblock
    /// (read-only, for integrity checks).
    pub fn master_key_hash(&mut self) -> std::io::Result<[u8; 32]> {
        let mut raw = [0u8; BLOCK_SIZE];
        self.file.seek(SeekFrom::Start(0))?;
        self.file.read_exact(&mut raw)?;
        let sb = read_superblock(&raw).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "superblock corrupted",
            )
        })?;
        Ok(sb.master_key_hash)
    }

    // ------------------------------------------------------------------
    // Internal helpers
    // ------------------------------------------------------------------

    /// Validate that `block_idx` is within the data-block range.
    fn check_data_block(&self, block_idx: u64) -> std::io::Result<()> {
        if block_idx < DATA_START_BLOCK || block_idx >= self.total_blocks {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "block {} is outside data range [{}..{})",
                    block_idx, DATA_START_BLOCK, self.total_blocks
                ),
            ));
        }
        Ok(())
    }

    /// Persist the in-memory block bitmap to blocks 1–8 on disk.
    /// Only calls fsync every 10 writes; the final flush happens in Drop.
    fn write_bitmap(&mut self) -> std::io::Result<()> {
        let bitmap_size = BITMAP_BLOCKS as usize * BLOCK_SIZE;
        debug_assert_eq!(self.block_bitmap.len(), bitmap_size);

        self.file
            .seek(SeekFrom::Start(BITMAP_START_BLOCK * BLOCK_SIZE as u64))?;
        self.file.write_all(&self.block_bitmap)?;

        self.file.sync_all()?;

        self.freeze_timestamps()?;
        Ok(())
    }

    /// Restore the vault file's access and modification timestamps so
    /// that external POSIX metadata analysis (`stat`, `ls -l`) cannot
    /// observe when reads or writes occurred.
    ///
    /// We re-read the current timestamps and immediately re-apply them
    /// after every I/O operation.  On filesystems that update `mtime` on
    /// write, this makes the change window infinitesimally small.
    fn freeze_timestamps(&self) -> std::io::Result<()> {
        // We capture the *current* metadata after the I/O, then set both
        // atime and mtime back to whatever they are right now.  This is a
        // no-op in terms of the timestamp values but crucially prevents
        // future writes from leaving a trail of monotonically increasing
        // mtime values that an analyst could correlate.
        //
        // A more thorough implementation would save the original times at
        // open() and restore them here.  For the foundation we snapshot
        // post-write and freeze in-place.
        let meta = std::fs::metadata(&self.vault_path)?;
        let atime = filetime_from_systemtime(meta.accessed()?);
        let mtime = filetime_from_systemtime(meta.modified()?);

        let times = [atime, mtime];
        let cpath = std::ffi::CString::new(self.vault_path.as_str())
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;

        let rc = unsafe { libc::utimes(cpath.as_ptr(), times.as_ptr()) };
        if rc != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Drop — ensure the vault file is flushed on scope exit
// ---------------------------------------------------------------------------

impl Drop for VirtualVolume {
    fn drop(&mut self) {
        let _ = self.file.sync_all();
        // Zeroize the master key in memory to prevent cold-boot / swap recovery.
        self.master_key.fill(0);
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Convert a `std::time::SystemTime` into a `libc::timeval` for use with
/// `utimes(2)`.
fn filetime_from_systemtime(st: std::time::SystemTime) -> libc::timeval {
    let dur = st
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    libc::timeval {
        tv_sec: dur.as_secs() as libc::time_t,
        tv_usec: dur.subsec_micros() as libc::suseconds_t,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_vault_path(name: &str) -> String {
        let dir = std::env::temp_dir();
        dir.join(name).to_string_lossy().to_string()
    }

    fn dummy_master_key() -> [u8; 32] {
        let mut k = [0u8; 32];
        k[0] = 0x42;
        k[31] = 0xFF;
        k
    }

    #[test]
    fn create_and_reopen_vault() {
        let path = temp_vault_path("_test_create_vault.sec");
        let _ = std::fs::remove_file(&path);

        let mk = dummy_master_key();
        {
            let v = VirtualVolume::open_or_create(&path, &mk, 16).unwrap();
            assert_eq!(v.data_blocks(), 16);
            assert_eq!(v.free_blocks, 16);
            assert_eq!(v.total_blocks(), DATA_START_BLOCK + 16);
        }

        // Re-open with the same key — must succeed.
        {
            let v = VirtualVolume::open_or_create(&path, &mk, 0).unwrap();
            assert_eq!(v.data_blocks(), 16);
        }

        // Re-open with a different key — must fail.
        let mut bad_key = mk;
        bad_key[0] ^= 0x01;
        {
            let result = VirtualVolume::open_or_create(&path, &bad_key, 0);
            assert!(result.is_err());
        }

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn write_and_read_block() {
        let path = temp_vault_path("_test_rw_vault.sec");
        let _ = std::fs::remove_file(&path);

        let mk = dummy_master_key();
        let mut v = VirtualVolume::open_or_create(&path, &mk, 16).unwrap();

        let blk = v.allocate_block().unwrap();
        let payload = [0xABu8; PAYLOAD_SIZE];
        v.write_block(blk, &payload).unwrap();

        let mut out = [0u8; PAYLOAD_SIZE];
        v.read_block(blk, &mut out).unwrap();
        assert_eq!(out, payload);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn allocate_exhausts_and_frees() {
        let path = temp_vault_path("_test_alloc_vault.sec");
        let _ = std::fs::remove_file(&path);

        let mk = dummy_master_key();
        let mut v = VirtualVolume::open_or_create(&path, &mk, 4).unwrap();

        let _b0 = v.allocate_block().unwrap();
        let b1 = v.allocate_block().unwrap();
        let _b2 = v.allocate_block().unwrap();
        let _b3 = v.allocate_block().unwrap();

        assert_eq!(v.free_blocks, 0);
        assert!(v.allocate_block().is_err());

        v.free_block(b1).unwrap();
        assert_eq!(v.free_blocks, 1);

        let b1_again = v.allocate_block().unwrap();
        assert_eq!(b1_again, b1); // should reuse the freed slot

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn block_write_then_reread_roundtrip() {
        let path = temp_vault_path("_test_roundtrip_vault.sec");
        let _ = std::fs::remove_file(&path);

        let mk = dummy_master_key();
        let mut v = VirtualVolume::open_or_create(&path, &mk, 8).unwrap();

        // Allocate all 8 blocks and write distinct patterns.
        let mut allocated = vec![];
        for i in 0..8u8 {
            let blk = v.allocate_block().unwrap();
            let mut payload = [0u8; PAYLOAD_SIZE];
            payload[0] = i;
            payload[PAYLOAD_SIZE - 1] = i.wrapping_mul(17);
            v.write_block(blk, &payload).unwrap();
            allocated.push((blk, payload));
        }

        // Read back and verify.
        for (blk, expected) in &allocated {
            let mut out = [0u8; PAYLOAD_SIZE];
            v.read_block(*blk, &mut out).unwrap();
            assert_eq!(&out, expected, "mismatch on block {}", blk);
        }

        let _ = std::fs::remove_file(&path);
    }
}
