//! Session rekeying for forward secrecy
//!
//! Per 1-SECURITY.md, sessions MUST rekey periodically:
//! - `REKEY_AFTER_TIME` (120s): Initiate rekey after this time
//! - `REKEY_AFTER_MESSAGES` (2^60): Initiate rekey after this many frames
//! - `REJECT_AFTER_TIME` (180s): Hard limit, reject old keys
//! - `REJECT_AFTER_MESSAGES` (2^64-1): MUST terminate session
//! - `OLD_KEY_RETENTION` (5s): Keep old keys for late packets

use std::time::Instant;

use blake2::{Blake2s256, Digest};
use crate::core::{
    CryptoError, MAX_EPOCH, OLD_KEY_RETENTION, REJECT_AFTER_MESSAGES, REJECT_AFTER_TIME,
    REKEY_AFTER_MESSAGES, REKEY_AFTER_TIME,
};
use zeroize::Zeroize;

use super::{SessionKey, SESSION_KEY_SIZE};

/// Tracks the current key epoch and when rekeying is needed.
#[derive(Debug)]
pub struct RekeyState {
    /// Current epoch number (increments on each rekey)
    epoch: u32,
    /// Time when current epoch started
    epoch_start: Instant,
    /// Number of messages sent in current epoch
    send_count: u64,
    /// Number of messages received in current epoch
    recv_count: u64,
}

impl RekeyState {
    /// Create a new rekey state starting at epoch 0.
    pub fn new() -> Self {
        Self {
            epoch: 0,
            epoch_start: Instant::now(),
            send_count: 0,
            recv_count: 0,
        }
    }

    /// Get the current epoch.
    pub fn epoch(&self) -> u32 {
        self.epoch
    }

    /// Get the send counter for the current epoch.
    pub fn send_count(&self) -> u64 {
        self.send_count
    }

    /// Get the receive counter for the current epoch.
    pub fn recv_count(&self) -> u64 {
        self.recv_count
    }

    /// Increment the send counter.
    ///
    /// Returns the counter value to use for this message.
    ///
    /// # Errors
    /// Returns `CounterExhaustion` if the counter has reached the hard limit.
    pub fn increment_send(&mut self) -> Result<u64, CryptoError> {
        if self.send_count == REJECT_AFTER_MESSAGES {
            return Err(CryptoError::CounterExhaustion);
        }
        let counter = self.send_count;
        self.send_count += 1;
        Ok(counter)
    }

    /// Record a received message counter.
    ///
    /// Note: Actual replay detection is handled by the replay window.
    pub fn record_recv(&mut self, counter: u64) {
        if counter >= self.recv_count {
            self.recv_count = counter + 1;
        }
    }

    /// Check if we should initiate a rekey (soft limit reached).
    pub fn should_rekey(&self) -> bool {
        let time_exceeded = self.epoch_start.elapsed() >= REKEY_AFTER_TIME;
        let messages_exceeded = self.send_count >= REKEY_AFTER_MESSAGES;
        time_exceeded || messages_exceeded
    }

    /// Check if the current keys are expired (hard limit reached).
    pub fn keys_expired(&self) -> bool {
        self.epoch_start.elapsed() >= REJECT_AFTER_TIME
    }

    /// Check if we can perform another rekey (epoch limit).
    pub fn can_rekey(&self) -> bool {
        self.epoch < MAX_EPOCH
    }

    /// Advance to the next epoch.
    ///
    /// Resets counters and updates epoch start time.
    ///
    /// # Errors
    /// Returns `EpochExhaustion` if the epoch counter has reached the limit.
    pub fn advance_epoch(&mut self) -> Result<(), CryptoError> {
        if self.epoch == MAX_EPOCH {
            return Err(CryptoError::EpochExhaustion);
        }
        self.epoch += 1;
        self.epoch_start = Instant::now();
        self.send_count = 0;
        self.recv_count = 0;
        Ok(())
    }
}

impl Default for RekeyState {
    fn default() -> Self {
        Self::new()
    }
}

/// Manages old keys during the transition period after a rekey.
pub struct OldKeyRetention {
    /// The old initiator key
    initiator_key: Option<SessionKey>,
    /// The old responder key
    responder_key: Option<SessionKey>,
    /// When the old keys were retained
    retained_at: Option<Instant>,
}

impl OldKeyRetention {
    /// Create a new retention manager with no old keys.
    pub fn new() -> Self {
        Self {
            initiator_key: None,
            responder_key: None,
            retained_at: None,
        }
    }

    /// Retain the current keys as old keys.
    pub fn retain(&mut self, initiator_key: SessionKey, responder_key: SessionKey) {
        self.initiator_key = Some(initiator_key);
        self.responder_key = Some(responder_key);
        self.retained_at = Some(Instant::now());
    }

    /// Get the old initiator key if still within retention window.
    pub fn old_initiator_key(&self) -> Option<&SessionKey> {
        if self.within_retention_window() {
            self.initiator_key.as_ref()
        } else {
            None
        }
    }

    /// Get the old responder key if still within retention window.
    pub fn old_responder_key(&self) -> Option<&SessionKey> {
        if self.within_retention_window() {
            self.responder_key.as_ref()
        } else {
            None
        }
    }

    /// Check if we're within the retention window.
    pub fn within_retention_window(&self) -> bool {
        self.retained_at
            .is_some_and(|t| t.elapsed() < OLD_KEY_RETENTION)
    }

    /// Clear old keys (call after retention window expires or explicitly).
    pub fn clear(&mut self) {
        self.initiator_key = None;
        self.responder_key = None;
        self.retained_at = None;
    }

    /// Check if old keys should be cleared due to expired retention.
    pub fn should_clear(&self) -> bool {
        self.retained_at
            .is_some_and(|t| t.elapsed() >= OLD_KEY_RETENTION)
    }

    /// Clear old keys if retention has expired.
    pub fn clear_if_expired(&mut self) {
        if self.should_clear() {
            self.clear();
        }
    }
}

impl Default for OldKeyRetention {
    fn default() -> Self {
        Self::new()
    }
}

/// Derive new session keys after a rekey.
///
/// Per 1-SECURITY.md:
/// ```text
/// (new_initiator_key, new_responder_key) = HKDF-Expand(
///     new_handshake_hash,
///     "nomad v1 rekey" || LE32(epoch),
///     64
/// )
/// ```
pub fn derive_rekey_keys(
    handshake_hash: &[u8],
    epoch: u32,
) -> Result<(SessionKey, SessionKey), CryptoError> {
    let label = b"nomad v1 rekey";
    let epoch_bytes = epoch.to_le_bytes();

    // HKDF-Expand using BLAKE2s
    let mut hasher1 = Blake2s256::new();
    hasher1.update(handshake_hash);
    hasher1.update(label);
    hasher1.update(epoch_bytes);
    hasher1.update([0x01]); // Counter byte
    let output1 = hasher1.finalize();

    let mut hasher2 = Blake2s256::new();
    hasher2.update(handshake_hash);
    hasher2.update(output1);
    hasher2.update(label);
    hasher2.update(epoch_bytes);
    hasher2.update([0x02]); // Counter byte
    let output2 = hasher2.finalize();

    let mut key_material = [0u8; 64];
    key_material[..32].copy_from_slice(&output1);
    key_material[32..].copy_from_slice(&output2);

    let mut initiator_key = [0u8; SESSION_KEY_SIZE];
    let mut responder_key = [0u8; SESSION_KEY_SIZE];
    initiator_key.copy_from_slice(&key_material[..32]);
    responder_key.copy_from_slice(&key_material[32..]);

    // Zeroize intermediate material
    key_material.zeroize();

    Ok((
        SessionKey::from_bytes(initiator_key),
        SessionKey::from_bytes(responder_key),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rekey_state_new() {
        let state = RekeyState::new();
        assert_eq!(state.epoch(), 0);
        assert_eq!(state.send_count(), 0);
        assert_eq!(state.recv_count(), 0);
        assert!(!state.should_rekey());
        assert!(!state.keys_expired());
        assert!(state.can_rekey());
    }

    #[test]
    fn test_increment_send() {
        let mut state = RekeyState::new();

        for i in 0..10 {
            let counter = state.increment_send().unwrap();
            assert_eq!(counter, i);
        }
        assert_eq!(state.send_count(), 10);
    }

    #[test]
    fn test_record_recv() {
        let mut state = RekeyState::new();

        state.record_recv(5);
        assert_eq!(state.recv_count(), 6); // max + 1

        state.record_recv(3); // Out of order, should not decrease
        assert_eq!(state.recv_count(), 6);

        state.record_recv(10);
        assert_eq!(state.recv_count(), 11);
    }

    #[test]
    fn test_advance_epoch() {
        let mut state = RekeyState::new();
        state.increment_send().unwrap();
        state.increment_send().unwrap();

        state.advance_epoch().unwrap();

        assert_eq!(state.epoch(), 1);
        assert_eq!(state.send_count(), 0);
        assert_eq!(state.recv_count(), 0);
    }

    #[test]
    fn test_old_key_retention() {
        let mut retention = OldKeyRetention::new();

        assert!(retention.old_initiator_key().is_none());
        assert!(!retention.within_retention_window());

        let key1 = SessionKey::from_bytes([0x01; SESSION_KEY_SIZE]);
        let key2 = SessionKey::from_bytes([0x02; SESSION_KEY_SIZE]);

        retention.retain(key1, key2);

        assert!(retention.within_retention_window());
        assert!(retention.old_initiator_key().is_some());
        assert!(retention.old_responder_key().is_some());
    }

    #[test]
    fn test_derive_rekey_keys() {
        let handshake_hash = [0x42u8; 32];

        let (key1_epoch0, key2_epoch0) = derive_rekey_keys(&handshake_hash, 0).unwrap();
        let (key1_epoch1, key2_epoch1) = derive_rekey_keys(&handshake_hash, 1).unwrap();

        // Different epochs should produce different keys
        assert_ne!(key1_epoch0.as_bytes(), key1_epoch1.as_bytes());
        assert_ne!(key2_epoch0.as_bytes(), key2_epoch1.as_bytes());

        // Same epoch should produce same keys
        let (key1_epoch0_again, key2_epoch0_again) = derive_rekey_keys(&handshake_hash, 0).unwrap();
        assert_eq!(key1_epoch0.as_bytes(), key1_epoch0_again.as_bytes());
        assert_eq!(key2_epoch0.as_bytes(), key2_epoch0_again.as_bytes());
    }

    #[test]
    fn test_derive_rekey_keys_different_hashes() {
        let hash1 = [0x01u8; 32];
        let hash2 = [0x02u8; 32];

        let (key1_h1, _) = derive_rekey_keys(&hash1, 0).unwrap();
        let (key1_h2, _) = derive_rekey_keys(&hash2, 0).unwrap();

        // Different handshake hashes should produce different keys
        assert_ne!(key1_h1.as_bytes(), key1_h2.as_bytes());
    }
}
