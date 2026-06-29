//! Anti-DoS recovery — epoch-based roll-forward without per-packet state.
//!
//! ## Problem
//! An attacker drops or replays packets.  With counter-based schemes (old design)
//! this either locks the ratchet or forces expensive catch-up.  With epoch-based
//! derivation the cost is O(gap) for any gap size.
//!
//! ## Solution
//! After reconnection Bob reads the peer's EpochID from the packet header.  If
//! `peer_epoch > local_epoch`, Bob locally rolls RootState_curr forward:
//!
//!   for _ in local..peer:
//!       RootState_curr = HKDF-Extract(salt="epoch_roll", ikm=RootState_curr)
//!       EpochID += 1
//!
//! This costs O(epoch_gap) hash operations — trivially cheap for any realistic gap
//! (10,000 epochs ≈ milliseconds).  The attacker gains nothing by dropping packets.

use crate::root_state;

/// Roll RootState_curr forward to `target_epoch`.  Each step is atomic
/// (locks both root_curr and epoch together).
/// Returns the new epoch ID after recovery, or u32::MAX on error.
pub fn recover_after_loss(target_epoch: u32) -> u32 {
    let e = root_state::read_epoch_id();
    if target_epoch <= e { return e; }
    let gap = target_epoch - e;
    if gap > 100_000 { return u32::MAX; }

    let mut last = e;
    for _ in 0..gap {
        let r = root_state::roll_epoch_forward(b"epoch_roll", b"LinkChat Epoch Roll");
        if r == u32::MAX { return u32::MAX; }
        last = r;
    }
    last
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::root_state;

    #[test]
    fn recover_forward() {
        let key = [1u8; 32];
        root_state::set_root_state_curr(key);
        root_state::set_epoch_id(0);

        let new_e = recover_after_loss(5);
        assert_eq!(new_e, 5);
        assert_eq!(root_state::read_epoch_id(), 5);
        assert_ne!(root_state::read_root_state_curr(), key);
    }

    #[test]
    fn noop_if_same() {
        root_state::set_root_state_curr([2u8; 32]);
        root_state::set_epoch_id(10);
        assert_eq!(recover_after_loss(5), 10);
    }

    #[test]
    fn cap_enforced() {
        root_state::set_root_state_curr([3u8; 32]);
        root_state::set_epoch_id(0);
        assert_eq!(recover_after_loss(200_000), u32::MAX);
    }
}
