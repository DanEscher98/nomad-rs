//! Session rekeying for forward secrecy
//!
//! Per 1-SECURITY.md, sessions MUST rekey periodically:
//! - `REKEY_AFTER_TIME` (120s): Initiate rekey after this time
//! - `REKEY_AFTER_MESSAGES` (2^60): Initiate rekey after this many frames
//! - `REJECT_AFTER_TIME` (180s): Hard limit, reject old keys
//! - `REJECT_AFTER_MESSAGES` (2^64-1): MUST terminate session
//! - `OLD_KEY_RETENTION` (5s): Keep old keys for late packets

use std::time::Instant;

use hkdf::Hkdf;
use sha2::Sha256;
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

/// Derive new session keys after a rekey with PCS protection.
///
/// This function provides Post-Compromise Security (PCS) by mixing in the
/// `rekey_auth_key` which is derived from the static DH during handshake.
/// An attacker who compromises session keys cannot derive future rekey keys
/// without knowing the static DH secret.
///
/// Per 1-SECURITY.md (PCS fix):
/// ```text
/// ikm = ephemeral_dh || rekey_auth_key
/// (new_initiator_key, new_responder_key) = HKDF-Expand(
///     ikm,
///     "nomad v1 rekey" || LE32(epoch),
///     64
/// )
/// ```
///
/// # Arguments
/// * `ephemeral_dh` - The DH result from the rekey ephemeral exchange
/// * `rekey_auth_key` - Key derived from static DH during initial handshake
/// * `epoch` - The new epoch number
pub fn derive_rekey_keys(
    ephemeral_dh: &[u8; 32],
    rekey_auth_key: &[u8; 32],
    epoch: u32,
) -> Result<(SessionKey, SessionKey), CryptoError> {
    // Concatenate ephemeral_dh || rekey_auth_key as IKM
    // This ensures PCS: attacker needs fresh ephemeral DH AND static DH secret
    let mut ikm = [0u8; 64];
    ikm[..32].copy_from_slice(ephemeral_dh);
    ikm[32..].copy_from_slice(rekey_auth_key);

    // Build info: "nomad v1 rekey" || LE32(epoch)
    let label = b"nomad v1 rekey";
    let epoch_bytes = epoch.to_le_bytes();
    let mut info = Vec::with_capacity(label.len() + 4);
    info.extend_from_slice(label);
    info.extend_from_slice(&epoch_bytes);

    // HKDF-Expand only (no Extract step) with SHA-256
    // The ikm is treated as a PRK directly per the spec
    let hk = Hkdf::<Sha256>::from_prk(&ikm)
        .map_err(|_| CryptoError::KeyDerivationFailed)?;
    let mut key_material = [0u8; 64];
    hk.expand(&info, &mut key_material)
        .map_err(|_| CryptoError::KeyDerivationFailed)?;

    let mut initiator_key = [0u8; SESSION_KEY_SIZE];
    let mut responder_key = [0u8; SESSION_KEY_SIZE];
    initiator_key.copy_from_slice(&key_material[..32]);
    responder_key.copy_from_slice(&key_material[32..]);

    // Zeroize intermediate material
    ikm.zeroize();
    key_material.zeroize();

    Ok((
        SessionKey::from_bytes(initiator_key),
        SessionKey::from_bytes(responder_key),
    ))
}

/// Derive the rekey authentication key from static DH secret.
///
/// This key is derived during handshake completion and used for PCS.
/// It ensures that even if session keys are compromised, an attacker
/// cannot derive future rekey keys without the static DH secret.
///
/// Per 1-SECURITY.md (PCS fix):
/// ```text
/// rekey_auth_key = HKDF-Expand(
///     static_dh_secret,   // DH(s_initiator, S_responder)
///     "nomad v1 rekey auth",
///     32
/// )
/// ```
pub fn derive_rekey_auth_key(static_dh_secret: &[u8; 32]) -> [u8; 32] {
    let info = b"nomad v1 rekey auth";

    // HKDF-Expand only (no Extract step) with SHA-256
    // The static_dh_secret is treated as a PRK directly per the spec
    let hk = Hkdf::<Sha256>::from_prk(static_dh_secret)
        .expect("32 bytes is valid PRK length for SHA-256 HKDF");
    let mut rekey_auth_key = [0u8; 32];
    hk.expand(info, &mut rekey_auth_key)
        .expect("32 bytes is valid output length for SHA-256 HKDF");

    rekey_auth_key
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
        let ephemeral_dh = [0x42u8; 32];
        let rekey_auth_key = [0x33u8; 32];

        let (key1_epoch0, key2_epoch0) = derive_rekey_keys(&ephemeral_dh, &rekey_auth_key, 0).unwrap();
        let (key1_epoch1, key2_epoch1) = derive_rekey_keys(&ephemeral_dh, &rekey_auth_key, 1).unwrap();

        // Different epochs should produce different keys
        assert_ne!(key1_epoch0.as_bytes(), key1_epoch1.as_bytes());
        assert_ne!(key2_epoch0.as_bytes(), key2_epoch1.as_bytes());

        // Same epoch should produce same keys
        let (key1_epoch0_again, key2_epoch0_again) = derive_rekey_keys(&ephemeral_dh, &rekey_auth_key, 0).unwrap();
        assert_eq!(key1_epoch0.as_bytes(), key1_epoch0_again.as_bytes());
        assert_eq!(key2_epoch0.as_bytes(), key2_epoch0_again.as_bytes());
    }

    #[test]
    fn test_derive_rekey_keys_different_ephemeral_dh() {
        let ephemeral_dh1 = [0x01u8; 32];
        let ephemeral_dh2 = [0x02u8; 32];
        let rekey_auth_key = [0x33u8; 32];

        let (key1_dh1, _) = derive_rekey_keys(&ephemeral_dh1, &rekey_auth_key, 0).unwrap();
        let (key1_dh2, _) = derive_rekey_keys(&ephemeral_dh2, &rekey_auth_key, 0).unwrap();

        // Different ephemeral DH should produce different keys
        assert_ne!(key1_dh1.as_bytes(), key1_dh2.as_bytes());
    }

    #[test]
    fn test_derive_rekey_keys_pcs() {
        // Test that different rekey_auth_keys produce different rekey keys
        // This verifies the PCS property
        let ephemeral_dh = [0x42u8; 32];
        let auth_key1 = [0x01u8; 32];
        let auth_key2 = [0x02u8; 32];

        let (key1_auth1, _) = derive_rekey_keys(&ephemeral_dh, &auth_key1, 0).unwrap();
        let (key1_auth2, _) = derive_rekey_keys(&ephemeral_dh, &auth_key2, 0).unwrap();

        // Different rekey_auth_keys should produce different keys
        // This is the core PCS property: knowing session keys but not rekey_auth_key
        // means you cannot derive future keys
        assert_ne!(key1_auth1.as_bytes(), key1_auth2.as_bytes());
    }

    #[test]
    fn test_derive_rekey_auth_key() {
        let static_dh1 = [0x01u8; 32];
        let static_dh2 = [0x02u8; 32];

        let auth_key1 = derive_rekey_auth_key(&static_dh1);
        let auth_key2 = derive_rekey_auth_key(&static_dh2);

        // Different static DH secrets should produce different auth keys
        assert_ne!(auth_key1, auth_key2);

        // Same static DH secret should produce same auth key (deterministic)
        let auth_key1_again = derive_rekey_auth_key(&static_dh1);
        assert_eq!(auth_key1, auth_key1_again);
    }

    #[test]
    fn test_pcs_property() {
        // Simulate the PCS attack scenario:
        // Attacker knows: ephemeral_dh for the rekey
        // Attacker doesn't know: rekey_auth_key (derived from static DH)
        // Attacker cannot derive: new rekey keys

        let ephemeral_dh = [0x42u8; 32];
        let real_static_dh = [0xABu8; 32];
        let attacker_guess_dh = [0xCDu8; 32];

        let real_auth_key = derive_rekey_auth_key(&real_static_dh);
        let attacker_auth_key = derive_rekey_auth_key(&attacker_guess_dh);

        // Real keys for epoch 1
        let (real_key1, _) = derive_rekey_keys(&ephemeral_dh, &real_auth_key, 1).unwrap();

        // Attacker's attempt at epoch 1 keys (with wrong auth key)
        let (attacker_key1, _) = derive_rekey_keys(&ephemeral_dh, &attacker_auth_key, 1).unwrap();

        // Keys must be different - attacker cannot derive the correct keys
        assert_ne!(real_key1.as_bytes(), attacker_key1.as_bytes());
    }

    // ===== Test Vector Validation =====
    // These tests validate against the official NOMAD protocol test vectors
    // from nomad-specs/tests/vectors/rekey_vectors.json5

    /// Helper to decode hex string to bytes
    fn hex_to_bytes(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn test_vector_rekey_auth_key() {
        // From intermediate_values in rekey_vectors.json5
        let static_dh = hex_to_bytes("57fbeea357c6ca4af3654988d78e020ccc6f4bc56db385bff4a46084b1187266");
        let expected_auth_key = hex_to_bytes("48c391a58d3e6fe3e5c463cd874b4565b752da33d63b9d93f9a469549ebbbe09");

        let mut static_dh_arr = [0u8; 32];
        static_dh_arr.copy_from_slice(&static_dh);

        let auth_key = derive_rekey_auth_key(&static_dh_arr);

        assert_eq!(
            auth_key.as_slice(),
            expected_auth_key.as_slice(),
            "rekey_auth_key derivation doesn't match test vector"
        );
    }

    #[test]
    fn test_vector_epoch_1() {
        // epoch_0_to_1 vector from rekey_vectors.json5
        let ephemeral_dh = hex_to_bytes("813c560b94aec760c9a8d12a09bb4c2be3bfc35eb6983ceb264a13046d3aaa75");
        let rekey_auth_key = hex_to_bytes("48c391a58d3e6fe3e5c463cd874b4565b752da33d63b9d93f9a469549ebbbe09");
        let expected_initiator_key = hex_to_bytes("ba7ba9959a0338866994033dc46c15df92e6a08b4d5041d5e52070001187c312");
        let expected_responder_key = hex_to_bytes("91f2e4123a04abe6343003d6ff5793af7aae75ede7fdc6737aaf24964d9285f8");

        let mut ephemeral_dh_arr = [0u8; 32];
        let mut rekey_auth_key_arr = [0u8; 32];
        ephemeral_dh_arr.copy_from_slice(&ephemeral_dh);
        rekey_auth_key_arr.copy_from_slice(&rekey_auth_key);

        let (initiator_key, responder_key) = derive_rekey_keys(&ephemeral_dh_arr, &rekey_auth_key_arr, 1).unwrap();

        assert_eq!(
            initiator_key.as_bytes(),
            expected_initiator_key.as_slice(),
            "epoch 1 initiator key doesn't match test vector"
        );
        assert_eq!(
            responder_key.as_bytes(),
            expected_responder_key.as_slice(),
            "epoch 1 responder key doesn't match test vector"
        );
    }

    #[test]
    fn test_vector_epoch_2() {
        // epoch_1_to_2_pcs_case vector from rekey_vectors.json5
        let ephemeral_dh = hex_to_bytes("7efd5673c47236ad6f9bf85e945074615c1943c528a87cc0dc9084ad278d266e");
        let rekey_auth_key = hex_to_bytes("48c391a58d3e6fe3e5c463cd874b4565b752da33d63b9d93f9a469549ebbbe09");
        let expected_initiator_key = hex_to_bytes("206c3c4f0838aaf5b039bad2ecd1a387d6f784afbf1d283dc0a438ad45f4db3e");
        let expected_responder_key = hex_to_bytes("786554075c38e73a735b26cbfd650c9fd0f8909227e498487007fc2adfec661d");

        let mut ephemeral_dh_arr = [0u8; 32];
        let mut rekey_auth_key_arr = [0u8; 32];
        ephemeral_dh_arr.copy_from_slice(&ephemeral_dh);
        rekey_auth_key_arr.copy_from_slice(&rekey_auth_key);

        let (initiator_key, responder_key) = derive_rekey_keys(&ephemeral_dh_arr, &rekey_auth_key_arr, 2).unwrap();

        assert_eq!(
            initiator_key.as_bytes(),
            expected_initiator_key.as_slice(),
            "epoch 2 initiator key doesn't match test vector"
        );
        assert_eq!(
            responder_key.as_bytes(),
            expected_responder_key.as_slice(),
            "epoch 2 responder key doesn't match test vector"
        );
    }

    #[test]
    fn test_vector_epoch_100() {
        // epoch_high_number vector from rekey_vectors.json5
        let ephemeral_dh = hex_to_bytes("0038038a95c66833de6cd4a4743226d03d952d35d1885876f63b95deea271e3f");
        let rekey_auth_key = hex_to_bytes("48c391a58d3e6fe3e5c463cd874b4565b752da33d63b9d93f9a469549ebbbe09");
        let expected_initiator_key = hex_to_bytes("dda7dd785c4c5f75096c0ea88023b1558e26bb84f4c4eb72ba7977c6947abc1a");
        let expected_responder_key = hex_to_bytes("110c7c42998204153892f1ac84634c355ed1b279174befd2f27936073567e54f");

        let mut ephemeral_dh_arr = [0u8; 32];
        let mut rekey_auth_key_arr = [0u8; 32];
        ephemeral_dh_arr.copy_from_slice(&ephemeral_dh);
        rekey_auth_key_arr.copy_from_slice(&rekey_auth_key);

        let (initiator_key, responder_key) = derive_rekey_keys(&ephemeral_dh_arr, &rekey_auth_key_arr, 100).unwrap();

        assert_eq!(
            initiator_key.as_bytes(),
            expected_initiator_key.as_slice(),
            "epoch 100 initiator key doesn't match test vector"
        );
        assert_eq!(
            responder_key.as_bytes(),
            expected_responder_key.as_slice(),
            "epoch 100 responder key doesn't match test vector"
        );
    }
}
