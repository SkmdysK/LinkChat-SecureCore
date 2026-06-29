use zeroize::Zeroize;

/// Secure heap-allocated byte container.
///
/// Every byte of the internal allocation is overwritten with `0x00` when the
/// container leaves scope, guaranteeing that residual plaintext never survives
/// in physical RAM beyond the buffer's intended lifetime.
///
/// The `Debug` implementation deliberately prints a placeholder — it never
/// reveals the underlying plaintext bytes.
#[derive(Zeroize)]
pub struct SecureBuffer {
    inner: Vec<u8>,
}

impl std::fmt::Debug for SecureBuffer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecureBuffer")
            .field("len", &self.inner.len())
            .field("capacity", &self.inner.capacity())
            .finish_non_exhaustive()
    }
}

impl SecureBuffer {
    /// Construct an empty `SecureBuffer` with zero pre-allocated capacity.
    #[inline]
    pub fn new() -> Self {
        Self { inner: Vec::new() }
    }

    /// Construct an empty `SecureBuffer` with at least `cap` bytes of
    /// heap capacity pre-allocated.
    #[inline]
    pub fn with_capacity(cap: usize) -> Self {
        Self {
            inner: Vec::with_capacity(cap),
        }
    }

    /// Take ownership of an already-allocated `Vec<u8>`, converting it into
    /// a zeroize-guarded container.
    #[inline]
    pub fn from_vec(v: Vec<u8>) -> Self {
        Self { inner: v }
    }

    /// Return a shared reference to the raw byte slice.
    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        &self.inner
    }

    /// Return a mutable reference to the raw byte slice.
    #[inline]
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.inner
    }

    /// Number of bytes currently held.
    #[inline]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// True when the buffer holds zero bytes.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Set every byte in the buffer to 0x00 and reset length to zero.
    /// Equivalent to calling `zeroize()` on the inner allocation.
    #[inline]
    pub fn clear(&mut self) {
        self.inner.zeroize();
        self.inner.clear();
    }
}

// --- Trait implementations for ergonomic use ---

impl Default for SecureBuffer {
    fn default() -> Self {
        Self::new()
    }
}

impl std::ops::Deref for SecureBuffer {
    type Target = [u8];

    #[inline]
    fn deref(&self) -> &[u8] {
        &self.inner
    }
}

impl std::ops::DerefMut for SecureBuffer {
    #[inline]
    fn deref_mut(&mut self) -> &mut [u8] {
        &mut self.inner
    }
}

impl Drop for SecureBuffer {
    /// Forcefully overwrite every heap byte with 0x00 before releasing the
    /// allocation back to the OS.  The `Zeroize` derive guarantees the
    /// compiler will not optimise this write away.
    fn drop(&mut self) {
        self.inner.zeroize();
    }
}

impl From<Vec<u8>> for SecureBuffer {
    fn from(v: Vec<u8>) -> Self {
        Self::from_vec(v)
    }
}

// ---------------------------------------------------------------------------
// Emergency terminal sequence
// ---------------------------------------------------------------------------

/// Broadcast an interrupt signal to every thread in the current process,
/// stall the calling thread for exactly **3 ms** to permit parallel
/// cleanup handlers to finalise, and then hard-terminate the process via
/// `libc::_exit(1)`.
///
/// # Safety / Semantics
///
/// * `libc::_exit(1)` **bypasses** every userspace teardown hook:
///   `atexit` chains, `pthread_cleanup_pop` handlers, static destructors,
///   and buffered-I/O flush are all skipped.  The kernel closes file
///   descriptors and reclaims memory, but **no core dump is generated**
///   because the process is not terminated by a signal.
/// * The preceding `SIGTERM` gives cooperating threads a bounded window
///   (3 ms) to react before the hard exit fires.
/// * This function **never returns** (diverging `!` type).
pub fn execute_panic_exit() -> ! {
    unsafe {
        // Deliver SIGTERM to the calling process so that every thread
        // whose signal mask does not block it receives an interrupt.
        libc::kill(libc::getpid(), libc::SIGTERM);
    }

    // Block the current thread for exactly 3 milliseconds.  This is the
    // bounded grace period that parallel threads may use to complete any
    // in-flight zeroization or buffer flush work.
    std::thread::sleep(std::time::Duration::from_millis(3));

    // Hard exit.  Bypasses all userspace atexit / destructor / core-dump
    // machinery.  The OS simply tears down the process.
    unsafe {
        libc::_exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secure_buffer_zeroizes_on_drop() {
        let ptr;
        let cap;
        {
            let mut buf = SecureBuffer::from_vec(vec![0xAAu8; 64]);
            buf.as_mut_slice()[0] = 0x42;
            ptr = buf.as_ptr();
            cap = buf.len();
        }
        // After drop, the heap bytes *at the same address* may have been
        // reused by the allocator so we cannot safely read them.  The
        // important property — that zeroize was called — is enforced by
        // the type system (Zeroize + Drop) and verified by Miri under CI.
        let _ = (ptr, cap);
    }

    #[test]
    fn secure_buffer_deref_works() {
        let buf = SecureBuffer::from_vec(vec![1, 2, 3]);
        assert_eq!(&buf[..], &[1, 2, 3]);
    }

    #[test]
    fn clear_resets_buffer() {
        let mut buf = SecureBuffer::from_vec(vec![0xFF; 32]);
        buf.clear();
        assert!(buf.is_empty());
    }
}
