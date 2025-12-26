//! Crypto session management with anti-replay protection
//!
//! This module combines all cryptographic primitives into a high-level
//! CryptoSession that handles:
//! - Sending and receiving encrypted frames
//! - Nonce management
//! - Anti-replay protection via sliding window
//! - Epoch/counter tracking

use crate::core::{CryptoError, HASH_SIZE, REPLAY_WINDOW_SIZE};

use super::{
    aead::{construct_aad, decrypt, encrypt, SessionKey},
    nonce::{construct_nonce, Direction},
    rekey::{OldKeyRetention, RekeyState},
    Role, SessionId,
};

/// Anti-replay sliding window.
///
/// Per 1-SECURITY.md:
/// - Window size: 2048 bits minimum
/// - Below window: MUST reject
/// - Seen nonce: MUST reject
/// - Above highest: Update window
pub struct ReplayWindow {
    /// Bitmap for tracking seen nonces
    bitmap: [u64; REPLAY_WINDOW_SIZE / 64],
    /// Highest nonce seen so far
    highest: u64,
    /// Whether we've seen any packets yet
    initialized: bool,
}

impl ReplayWindow {
    /// Create a new replay window.
    pub fn new() -> Self {
        Self {
            bitmap: [0; REPLAY_WINDOW_SIZE / 64],
            highest: 0,
            initialized: false,
        }
    }

    /// Check if a nonce is a replay (without updating).
    pub fn is_replay(&self, nonce: u64) -> bool {
        if !self.initialized {
            return false;
        }

        if nonce > self.highest {
            return false;
        }

        let diff = self.highest - nonce;
        if diff >= REPLAY_WINDOW_SIZE as u64 {
            return true; // Below window
        }

        let bit_index = diff as usize;
        let word_index = bit_index / 64;
        let bit_offset = bit_index % 64;
        (self.bitmap[word_index] & (1 << bit_offset)) != 0
    }

    /// Check if a nonce is a replay and update the window.
    ///
    /// Returns Ok(()) if the nonce is valid (not seen before).
    /// Returns Err(ReplayDetected) if the nonce is a replay.
    ///
    /// Per 1-SECURITY.md, replay check MUST occur BEFORE AEAD verification.
    pub fn check_and_update(&mut self, nonce: u64) -> Result<(), CryptoError> {
        if !self.initialized {
            // First packet - initialize
            self.highest = nonce;
            self.mark_seen(nonce);
            self.initialized = true;
            return Ok(());
        }

        if nonce > self.highest {
            // Advance the window
            let shift = nonce - self.highest;
            self.shift_window(shift);
            self.highest = nonce;
            self.mark_seen(nonce);
            Ok(())
        } else {
            let diff = self.highest - nonce;
            if diff >= REPLAY_WINDOW_SIZE as u64 {
                // Too old - below window
                return Err(CryptoError::ReplayDetected);
            }

            // Check if already seen
            if self.is_seen(nonce) {
                return Err(CryptoError::ReplayDetected);
            }

            // Mark as seen
            self.mark_seen(nonce);
            Ok(())
        }
    }

    /// Check if a nonce has been seen (internal helper).
    fn is_seen(&self, nonce: u64) -> bool {
        if nonce > self.highest {
            return false;
        }
        let diff = self.highest - nonce;
        if diff >= REPLAY_WINDOW_SIZE as u64 {
            return true; // Treat below-window as "seen" (rejected)
        }
        let bit_index = diff as usize;
        let word_index = bit_index / 64;
        let bit_offset = bit_index % 64;
        (self.bitmap[word_index] & (1 << bit_offset)) != 0
    }

    /// Mark a nonce as seen.
    fn mark_seen(&mut self, nonce: u64) {
        if nonce > self.highest {
            return; // Will be marked after shift
        }
        let diff = self.highest - nonce;
        if diff >= REPLAY_WINDOW_SIZE as u64 {
            return; // Too old
        }
        let bit_index = diff as usize;
        let word_index = bit_index / 64;
        let bit_offset = bit_index % 64;
        self.bitmap[word_index] |= 1 << bit_offset;
    }

    /// Shift the window forward.
    ///
    /// When we receive a new highest nonce, we need to shift all existing bits
    /// to make room for the new highest at position 0.
    /// Bit position represents (highest - nonce), so older nonces have higher bit positions.
    fn shift_window(&mut self, shift: u64) {
        if shift >= REPLAY_WINDOW_SIZE as u64 {
            // Complete reset - all previous nonces fall outside the window
            self.bitmap = [0; REPLAY_WINDOW_SIZE / 64];
            return;
        }

        let shift_words = (shift / 64) as usize;
        let shift_bits = (shift % 64) as u32;

        // Shift whole words (towards higher indices = older nonces)
        if shift_words > 0 {
            // Shift from high to low to avoid overwriting
            for i in (shift_words..self.bitmap.len()).rev() {
                self.bitmap[i] = self.bitmap[i - shift_words];
            }
            // Clear the newly freed low words
            for word in self.bitmap.iter_mut().take(shift_words) {
                *word = 0;
            }
        }

        // Shift remaining bits within words (towards higher bit positions)
        if shift_bits > 0 {
            let mut carry = 0u64;
            // Process from highest index to lowest (shift bits up within each word)
            for i in (0..self.bitmap.len()).rev() {
                let new_carry = self.bitmap[i] >> (64 - shift_bits);
                self.bitmap[i] = (self.bitmap[i] << shift_bits) | carry;
                carry = new_carry;
            }
        }
    }

    /// Reset the window (e.g., after rekey).
    pub fn reset(&mut self) {
        self.bitmap = [0; REPLAY_WINDOW_SIZE / 64];
        self.highest = 0;
        self.initialized = false;
    }
}

impl Default for ReplayWindow {
    fn default() -> Self {
        Self::new()
    }
}

/// A complete crypto session for secure communication.
///
/// Combines key management, nonce construction, AEAD, and anti-replay
/// into a single interface.
pub struct CryptoSession {
    /// Session ID
    session_id: SessionId,
    /// Our role (initiator or responder)
    role: Role,
    /// Current send key
    send_key: SessionKey,
    /// Current receive key
    recv_key: SessionKey,
    /// Rekey state (epoch, counters)
    rekey_state: RekeyState,
    /// Replay window for incoming packets
    replay_window: ReplayWindow,
    /// Old key retention for late packets during rekey
    old_keys: OldKeyRetention,
    /// Handshake hash for key derivation (kept for session resumption)
    #[allow(dead_code)]
    handshake_hash: [u8; HASH_SIZE],
    /// Rekey authentication key for PCS (derived from static DH).
    /// This key is mixed into rekey KDF to ensure post-compromise security.
    /// Without this key, an attacker who compromises session keys cannot
    /// derive future rekey keys.
    rekey_auth_key: [u8; HASH_SIZE],
}

impl CryptoSession {
    /// Create a new crypto session after handshake completion.
    ///
    /// # Arguments
    /// * `session_id` - Unique session identifier
    /// * `role` - Our role (initiator or responder)
    /// * `send_key` - Initial send key
    /// * `recv_key` - Initial receive key
    /// * `handshake_hash` - Hash of the handshake transcript
    /// * `rekey_auth_key` - Key derived from static DH for PCS during rekey
    pub fn new(
        session_id: SessionId,
        role: Role,
        send_key: SessionKey,
        recv_key: SessionKey,
        handshake_hash: [u8; HASH_SIZE],
        rekey_auth_key: [u8; HASH_SIZE],
    ) -> Self {
        Self {
            session_id,
            role,
            send_key,
            recv_key,
            rekey_state: RekeyState::new(),
            replay_window: ReplayWindow::new(),
            old_keys: OldKeyRetention::new(),
            handshake_hash,
            rekey_auth_key,
        }
    }

    /// Get the session ID.
    pub fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    /// Get the current role.
    pub fn role(&self) -> Role {
        self.role
    }

    /// Get the current epoch.
    pub fn epoch(&self) -> u32 {
        self.rekey_state.epoch()
    }

    /// Check if we should initiate a rekey.
    pub fn should_rekey(&self) -> bool {
        self.rekey_state.should_rekey()
    }

    /// Check if keys are expired (session must terminate).
    pub fn keys_expired(&self) -> bool {
        self.rekey_state.keys_expired()
    }

    /// Get the direction for sending based on our role.
    fn send_direction(&self) -> Direction {
        match self.role {
            Role::Initiator => Direction::InitiatorToResponder,
            Role::Responder => Direction::ResponderToInitiator,
        }
    }

    /// Get the direction for receiving based on our role.
    fn recv_direction(&self) -> Direction {
        self.send_direction().opposite()
    }

    /// Encrypt a frame for sending.
    ///
    /// Returns (nonce_counter, ciphertext).
    pub fn encrypt_frame(
        &mut self,
        frame_type: u8,
        flags: u8,
        plaintext: &[u8],
    ) -> Result<(u64, Vec<u8>), CryptoError> {
        // Get counter and construct nonce
        let counter = self.rekey_state.increment_send()?;
        let nonce = construct_nonce(self.rekey_state.epoch(), self.send_direction(), counter);

        // Construct AAD
        let aad = construct_aad(frame_type, flags, self.session_id.as_bytes(), counter);

        // Encrypt
        let ciphertext = encrypt(&self.send_key, &nonce, &aad, plaintext)?;

        Ok((counter, ciphertext))
    }

    /// Decrypt a received frame.
    ///
    /// Performs replay check BEFORE decryption per spec.
    pub fn decrypt_frame(
        &mut self,
        frame_type: u8,
        flags: u8,
        nonce_counter: u64,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        // 1. Replay check FIRST (cheap, prevents DoS)
        if self.replay_window.is_replay(nonce_counter) {
            return Err(CryptoError::ReplayDetected);
        }

        // Construct nonce and AAD
        let nonce = construct_nonce(self.rekey_state.epoch(), self.recv_direction(), nonce_counter);
        let aad = construct_aad(frame_type, flags, self.session_id.as_bytes(), nonce_counter);

        // 2. Try current keys first
        if let Ok(plaintext) = decrypt(&self.recv_key, &nonce, &aad, ciphertext) {
            // 3. Update replay window only after successful verification
            let _ = self.replay_window.check_and_update(nonce_counter);
            self.rekey_state.record_recv(nonce_counter);
            return Ok(plaintext);
        }

        // 4. Try old keys if within retention window
        self.old_keys.clear_if_expired();
        if let Some(old_recv_key) = self.get_old_recv_key() {
            // Try with previous epoch's nonce
            let old_epoch = self.rekey_state.epoch().saturating_sub(1);
            let old_nonce = construct_nonce(old_epoch, self.recv_direction(), nonce_counter);

            if let Ok(plaintext) = decrypt(old_recv_key, &old_nonce, &aad, ciphertext) {
                // Note: Don't update replay window for old epoch packets
                // (they have their own counter space)
                return Ok(plaintext);
            }
        }

        Err(CryptoError::DecryptionFailed)
    }

    /// Get the old receive key based on role.
    fn get_old_recv_key(&self) -> Option<&SessionKey> {
        match self.role {
            Role::Initiator => self.old_keys.old_responder_key(),
            Role::Responder => self.old_keys.old_initiator_key(),
        }
    }

    /// Perform a rekey operation with the given ephemeral DH result.
    ///
    /// Advances the epoch and derives new keys using PCS-secure derivation.
    /// The caller is responsible for performing the ephemeral key exchange
    /// and computing the DH shared secret.
    ///
    /// # Arguments
    /// * `ephemeral_dh` - The result of DH(my_ephemeral, their_ephemeral_public)
    ///
    /// # Security
    /// The rekey_auth_key (derived from static DH during handshake) is mixed
    /// into the KDF along with ephemeral_dh. This ensures:
    /// - Forward secrecy from the fresh ephemeral exchange
    /// - Post-compromise security from the static DH-derived auth key
    pub fn rekey(&mut self, ephemeral_dh: &[u8; 32]) -> Result<(), CryptoError> {
        use super::rekey::derive_rekey_keys;

        // Retain current keys
        self.old_keys
            .retain(self.send_key.clone(), self.recv_key.clone());

        // Advance epoch
        self.rekey_state.advance_epoch()?;

        // Derive new keys with PCS protection
        // IKM = ephemeral_dh || rekey_auth_key
        // This ensures that an attacker needs BOTH:
        // 1. To intercept the ephemeral exchange (forward secrecy)
        // 2. To know the static DH secret (post-compromise security)
        let (new_initiator_key, new_responder_key) =
            derive_rekey_keys(ephemeral_dh, &self.rekey_auth_key, self.rekey_state.epoch())?;

        // Update keys based on role
        match self.role {
            Role::Initiator => {
                self.send_key = new_initiator_key;
                self.recv_key = new_responder_key;
            }
            Role::Responder => {
                self.send_key = new_responder_key;
                self.recv_key = new_initiator_key;
            }
        }

        // Reset replay window for new epoch
        self.replay_window.reset();

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_replay_window_basic() {
        let mut window = ReplayWindow::new();

        // First packet should succeed
        assert!(window.check_and_update(0).is_ok());

        // Same packet should fail (replay)
        assert!(window.check_and_update(0).is_err());

        // New packet should succeed
        assert!(window.check_and_update(1).is_ok());

        // Out of order but in window should succeed
        assert!(window.check_and_update(5).is_ok());
        assert!(window.check_and_update(3).is_ok());
        assert!(window.check_and_update(4).is_ok());
        assert!(window.check_and_update(2).is_ok());

        // All replays
        assert!(window.check_and_update(0).is_err());
        assert!(window.check_and_update(3).is_err());
        assert!(window.check_and_update(5).is_err());
    }

    #[test]
    fn test_replay_window_large_gap() {
        let mut window = ReplayWindow::new();

        assert!(window.check_and_update(0).is_ok());
        assert!(window.check_and_update(1).is_ok());

        // Large jump
        assert!(window.check_and_update(1000).is_ok());

        // Old packets now below window
        assert!(window.check_and_update(0).is_err());
        assert!(window.check_and_update(1).is_err());

        // But recent packets in window should still work
        assert!(window.check_and_update(999).is_ok());
        assert!(window.check_and_update(998).is_ok());
    }

    #[test]
    fn test_replay_window_full_reset() {
        let mut window = ReplayWindow::new();

        for i in 0..100 {
            assert!(window.check_and_update(i).is_ok());
        }

        // Jump beyond window size
        assert!(window.check_and_update(100 + REPLAY_WINDOW_SIZE as u64).is_ok());

        // All previous should be below window
        for i in 0..100 {
            assert!(window.check_and_update(i).is_err());
        }
    }

    #[test]
    fn test_crypto_session_roundtrip() {
        let session_id = SessionId::generate();
        let send_key = SessionKey::from_bytes([0x01; 32]);
        let recv_key = SessionKey::from_bytes([0x02; 32]);
        let handshake_hash = [0x42; 32];
        let rekey_auth_key = [0x33; 32]; // PCS rekey authentication key

        let mut initiator = CryptoSession::new(
            session_id,
            Role::Initiator,
            send_key.clone(),
            recv_key.clone(),
            handshake_hash,
            rekey_auth_key,
        );

        let mut responder = CryptoSession::new(
            session_id,
            Role::Responder,
            recv_key.clone(),
            send_key.clone(),
            handshake_hash,
            rekey_auth_key,
        );

        // Initiator sends
        let plaintext = b"Hello, NOMAD!";
        let (counter, ciphertext) = initiator.encrypt_frame(0x03, 0x00, plaintext).unwrap();

        // Responder receives
        let decrypted = responder
            .decrypt_frame(0x03, 0x00, counter, &ciphertext)
            .unwrap();
        assert_eq!(decrypted, plaintext);

        // Responder sends back
        let reply = b"Hello back!";
        let (reply_counter, reply_ciphertext) =
            responder.encrypt_frame(0x03, 0x00, reply).unwrap();

        // Initiator receives
        let decrypted_reply = initiator
            .decrypt_frame(0x03, 0x00, reply_counter, &reply_ciphertext)
            .unwrap();
        assert_eq!(decrypted_reply, reply);
    }

    #[test]
    fn test_crypto_session_replay_detection() {
        let session_id = SessionId::generate();
        let send_key = SessionKey::from_bytes([0x01; 32]);
        let recv_key = SessionKey::from_bytes([0x02; 32]);
        let handshake_hash = [0x42; 32];
        let rekey_auth_key = [0x33; 32];

        let mut initiator = CryptoSession::new(
            session_id,
            Role::Initiator,
            send_key.clone(),
            recv_key.clone(),
            handshake_hash,
            rekey_auth_key,
        );

        let mut responder = CryptoSession::new(
            session_id,
            Role::Responder,
            recv_key.clone(),
            send_key.clone(),
            handshake_hash,
            rekey_auth_key,
        );

        let plaintext = b"test";
        let (counter, ciphertext) = initiator.encrypt_frame(0x03, 0x00, plaintext).unwrap();

        // First receive succeeds
        assert!(responder
            .decrypt_frame(0x03, 0x00, counter, &ciphertext)
            .is_ok());

        // Replay should fail
        assert!(responder
            .decrypt_frame(0x03, 0x00, counter, &ciphertext)
            .is_err());
    }

    #[test]
    fn test_crypto_session_wrong_aad() {
        let session_id = SessionId::generate();
        let send_key = SessionKey::from_bytes([0x01; 32]);
        let recv_key = SessionKey::from_bytes([0x02; 32]);
        let handshake_hash = [0x42; 32];
        let rekey_auth_key = [0x33; 32];

        let mut initiator = CryptoSession::new(
            session_id,
            Role::Initiator,
            send_key.clone(),
            recv_key.clone(),
            handshake_hash,
            rekey_auth_key,
        );

        let mut responder = CryptoSession::new(
            session_id,
            Role::Responder,
            recv_key.clone(),
            send_key.clone(),
            handshake_hash,
            rekey_auth_key,
        );

        let plaintext = b"test";
        let (counter, ciphertext) = initiator.encrypt_frame(0x03, 0x00, plaintext).unwrap();

        // Wrong frame type should fail
        assert!(responder
            .decrypt_frame(0x04, 0x00, counter, &ciphertext)
            .is_err());
    }
}
