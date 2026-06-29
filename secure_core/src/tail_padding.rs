//! Dynamic tail padding — appends TRNG physical noise to ciphertext.
//!
//! Each encrypted payload gets L ∈ [16, 512] bytes of OsRng randomness appended.
//! The padding length L is stored as a u16 in the last 2 bytes, so the receiver
//! can strip it deterministically.
//!
//! Wire format: [payload | noise_L | u16_le(L)]

use rand::RngCore;
use rand::rngs::OsRng;

const MIN_PAD: usize = 16;
const MAX_PAD: usize = 512;

/// Append random tail padding.  Returns a heap-allocated Vec.
pub fn add_tail_padding(payload: &[u8]) -> Vec<u8> {
    let l = (OsRng.next_u32() as usize % (MAX_PAD - MIN_PAD + 1)) + MIN_PAD;
    let mut out = Vec::with_capacity(payload.len() + l + 2);
    out.extend_from_slice(payload);

    // fill noise
    let old_len = out.len();
    out.resize(old_len + l, 0);
    OsRng.fill_bytes(&mut out[old_len..old_len + l]);

    // append L as u16 LE
    out.extend_from_slice(&(l as u16).to_le_bytes());
    out
}

/// Strip tail padding.  Returns the original payload or None if malformed.
pub fn strip_tail_padding(padded: &[u8]) -> Option<Vec<u8>> {
    if padded.len() < 4 { return None; } // minimum: 2B length trailer + at least 2B noise
    let l = u16::from_le_bytes([padded[padded.len() - 2], padded[padded.len() - 1]]) as usize;
    // Validate L is in the expected range [16, 512] and doesn't overflow
    if l < MIN_PAD || l > MAX_PAD { return None; }
    if padded.len() < 2 + l { return None; }
    let payload_end = padded.len() - 2 - l;
    Some(padded[..payload_end].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let data = b"encrypted message payload";
        let padded = add_tail_padding(data);
        let stripped = strip_tail_padding(&padded).expect("strip");
        assert_eq!(data.as_slice(), stripped);
    }

    #[test]
    fn length_in_range() {
        let data = b"test";
        let padded = add_tail_padding(data);
        let len_without_pad = padded.len() - 2;
        let pad_len = u16::from_le_bytes([padded[padded.len() - 2], padded[padded.len() - 1]]) as usize;
        assert!(pad_len >= 16 && pad_len <= 512);
        assert_eq!(data.len() + pad_len, len_without_pad);
    }
}
