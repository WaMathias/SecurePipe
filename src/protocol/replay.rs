// ============================================================
// SecurePipe - Replay Protection
// ============================================================
// Three independent checks, all must pass:
//   1. Sequence number strictly increasing per device
//   2. Timestamp within MAX_FRAME_AGE_SECS of current time
//   3. Nonce not seen before (sliding window cache)

use std::collections::{HashMap, VecDeque};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::{Result, SecurePipeError};
use crate::protocol::frame::{MAX_FRAME_AGE_SECS, NONCE_CACHE_SIZE, NONCE_SIZE};

/// Per-device state tracked by the replay guard
#[derive(Debug)]
struct DeviceState {
    last_sequence_nr: u32,
    nonce_cache: VecDeque<[u8; NONCE_SIZE]>,
}

impl DeviceState {
    fn new() -> Self {
        DeviceState {
            last_sequence_nr: 0,
            nonce_cache: VecDeque::with_capacity(NONCE_CACHE_SIZE),
        }
    }
}

/// Stateful replay guard. One instance per active connection.
/// Must be called for every received frame before decryption.
pub struct ReplayGuard {
    devices: HashMap<u32, DeviceState>,
}

impl ReplayGuard {
    pub fn new() -> Self {
        ReplayGuard {
            devices: HashMap::new(),
        }
    }

    /// Check a frame for replay. Returns Ok(()) if the frame is fresh,
    /// or an appropriate error if it should be rejected.
    ///
    /// IMPORTANT: Call this AFTER verifying the auth tag.
    /// Never process replay data from a frame with an invalid tag.
    pub fn check(
        &mut self,
        device_id: u32,
        sequence_nr: u32,
        timestamp: u64,
        nonce: &[u8; NONCE_SIZE],
    ) -> Result<()> {
        self.check_timestamp(timestamp)?;

        let state = self.devices.entry(device_id).or_insert_with(DeviceState::new);

        Self::check_sequence(state, sequence_nr)?;
        Self::check_nonce(state, nonce)?;

        // All checks passed - update state
        state.last_sequence_nr = sequence_nr;

        if state.nonce_cache.len() >= NONCE_CACHE_SIZE {
            state.nonce_cache.pop_front();
        }
        state.nonce_cache.push_back(*nonce);

        Ok(())
    }

    fn check_timestamp(&self, timestamp: u64) -> Result<()> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Frame must not be older than MAX_FRAME_AGE_SECS
        // Also reject frames from the future (clock skew > 5s)
        if now > timestamp && now - timestamp > MAX_FRAME_AGE_SECS {
            return Err(SecurePipeError::FrameStale(now - timestamp));
        }

        Ok(())
    }

    fn check_sequence(state: &DeviceState, sequence_nr: u32) -> Result<()> {
        // First frame from this device always passes
        if state.last_sequence_nr == 0 {
            return Ok(());
        }

        if sequence_nr <= state.last_sequence_nr {
            return Err(SecurePipeError::ReplaySequence(sequence_nr));
        }

        Ok(())
    }

    fn check_nonce(state: &DeviceState, nonce: &[u8; NONCE_SIZE]) -> Result<()> {
        if state.nonce_cache.contains(nonce) {
            return Err(SecurePipeError::ReplayNonce);
        }
        Ok(())
    }

    /// Remove state for a device (e.g. after disconnect)
    pub fn remove_device(&mut self, device_id: u32) {
        self.devices.remove(&device_id);
    }
}

impl Default for ReplayGuard {
    fn default() -> Self {
        Self::new()
    }
}
