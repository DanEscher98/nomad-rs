//! Noise_IK handshake implementation
//!
//! Per 1-SECURITY.md, NOMAD uses the Noise_IK pattern for 1-RTT mutual authentication.
//!
//! ```text
//! Noise_IK(s, rs):
//!   <- s                    # Responder's static key known to Initiator
//!   ...
//!   -> e, es, s, ss         # Initiator sends ephemeral + encrypted static
//!   <- e, ee, se            # Responder sends ephemeral, completes DH
//! ```
//!
//! After handshake, both parties derive session keys using HKDF.

use crate::core::{CryptoError, HASH_SIZE, PUBLIC_KEY_SIZE};
use snow::{Builder, HandshakeState};
use zeroize::Zeroize;

use super::{SessionKey, StaticKeypair, SESSION_KEY_SIZE};

/// Noise protocol pattern for NOMAD
const NOISE_PATTERN: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2s";

/// Result of a completed handshake
pub struct HandshakeResult {
    /// The handshake hash (used for key derivation)
    pub handshake_hash: [u8; HASH_SIZE],
}

/// Handshake state machine for the initiator (client).
pub struct InitiatorHandshake {
    state: HandshakeState,
}

impl InitiatorHandshake {
    /// Create a new initiator handshake.
    ///
    /// # Arguments
    /// * `local_keypair` - The initiator's static keypair
    /// * `remote_public` - The responder's known static public key
    pub fn new(
        local_keypair: &StaticKeypair,
        remote_public: &[u8; PUBLIC_KEY_SIZE],
    ) -> Result<Self, CryptoError> {
        let builder = Builder::new(NOISE_PATTERN.parse().unwrap());
        let state = builder
            .local_private_key(local_keypair.private_key())
            .remote_public_key(remote_public)
            .build_initiator()
            .map_err(|e| CryptoError::HandshakeFailed(e.to_string()))?;

        Ok(Self { state })
    }

    /// Generate the first handshake message (-> e, es, s, ss).
    ///
    /// # Arguments
    /// * `payload` - Optional payload to include (state type ID, extensions)
    ///
    /// # Returns
    /// The handshake message bytes to send
    pub fn write_message(&mut self, payload: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let mut buf = vec![0u8; 65535];
        let len = self
            .state
            .write_message(payload, &mut buf)
            .map_err(|e| CryptoError::HandshakeFailed(e.to_string()))?;
        buf.truncate(len);
        Ok(buf)
    }

    /// Process the handshake response (<- e, ee, se).
    ///
    /// # Arguments
    /// * `message` - The handshake response from the responder
    ///
    /// # Returns
    /// The payload from the responder and the handshake result
    pub fn read_message(mut self, message: &[u8]) -> Result<(Vec<u8>, HandshakeResult), CryptoError> {
        let mut payload = vec![0u8; 65535];
        let len = self
            .state
            .read_message(message, &mut payload)
            .map_err(|e| CryptoError::HandshakeFailed(e.to_string()))?;
        payload.truncate(len);

        // Get the handshake hash BEFORE transitioning to transport mode
        let hash_slice = self.state.get_handshake_hash();
        let mut handshake_hash = [0u8; HASH_SIZE];
        handshake_hash.copy_from_slice(hash_slice);

        // Verify handshake is complete
        let _transport = self
            .state
            .into_transport_mode()
            .map_err(|e| CryptoError::HandshakeFailed(e.to_string()))?;

        Ok((payload, HandshakeResult { handshake_hash }))
    }
}

/// Handshake state machine for the responder (server).
pub struct ResponderHandshake {
    state: HandshakeState,
}

impl ResponderHandshake {
    /// Create a new responder handshake.
    ///
    /// # Arguments
    /// * `local_keypair` - The responder's static keypair
    pub fn new(local_keypair: &StaticKeypair) -> Result<Self, CryptoError> {
        let builder = Builder::new(NOISE_PATTERN.parse().unwrap());
        let state = builder
            .local_private_key(local_keypair.private_key())
            .build_responder()
            .map_err(|e| CryptoError::HandshakeFailed(e.to_string()))?;

        Ok(Self { state })
    }

    /// Process the initiator's handshake message (-> e, es, s, ss).
    ///
    /// # Arguments
    /// * `message` - The handshake initiation from the initiator
    ///
    /// # Returns
    /// The payload from the initiator and the remote static public key
    pub fn read_message(&mut self, message: &[u8]) -> Result<(Vec<u8>, [u8; PUBLIC_KEY_SIZE]), CryptoError> {
        let mut payload = vec![0u8; 65535];
        let len = self
            .state
            .read_message(message, &mut payload)
            .map_err(|e| CryptoError::HandshakeFailed(e.to_string()))?;
        payload.truncate(len);

        // Get the remote static public key
        let remote_static = self
            .state
            .get_remote_static()
            .ok_or_else(|| CryptoError::HandshakeFailed("no remote static key".into()))?;

        let mut remote_public = [0u8; PUBLIC_KEY_SIZE];
        remote_public.copy_from_slice(remote_static);

        Ok((payload, remote_public))
    }

    /// Generate the handshake response (<- e, ee, se).
    ///
    /// # Arguments
    /// * `payload` - Optional payload to include (ack, negotiated extensions)
    ///
    /// # Returns
    /// The handshake response bytes and the handshake result
    pub fn write_message(mut self, payload: &[u8]) -> Result<(Vec<u8>, HandshakeResult), CryptoError> {
        let mut buf = vec![0u8; 65535];
        let len = self
            .state
            .write_message(payload, &mut buf)
            .map_err(|e| CryptoError::HandshakeFailed(e.to_string()))?;
        buf.truncate(len);

        // Get the handshake hash BEFORE transitioning to transport mode
        let hash_slice = self.state.get_handshake_hash();
        let mut handshake_hash = [0u8; HASH_SIZE];
        handshake_hash.copy_from_slice(hash_slice);

        // Verify handshake is complete
        let _transport = self
            .state
            .into_transport_mode()
            .map_err(|e| CryptoError::HandshakeFailed(e.to_string()))?;

        Ok((buf, HandshakeResult { handshake_hash }))
    }
}

/// Session keys derived from the Noise handshake.
///
/// Per 1-SECURITY.md:
/// ```text
/// (initiator_key, responder_key) = HKDF-Expand(
///     handshake_hash,
///     "nomad v1 session keys",
///     64
/// )
/// ```
///
/// Additionally, for PCS (Post-Compromise Security), we derive:
/// ```text
/// rekey_auth_key = HKDF-Expand(
///     static_dh_secret,   // DH(s_initiator, S_responder)
///     "nomad v1 rekey auth",
///     32
/// )
/// ```
pub struct SessionKeys {
    /// Key for initiator → responder messages
    pub initiator_key: SessionKey,
    /// Key for responder → initiator messages
    pub responder_key: SessionKey,
    /// The handshake hash (stored for rekeying)
    pub handshake_hash: [u8; HASH_SIZE],
    /// Rekey authentication key for PCS (derived from static DH)
    pub rekey_auth_key: [u8; HASH_SIZE],
}

impl SessionKeys {
    /// Derive session keys from the handshake result and static DH secret.
    ///
    /// Uses SHA-256 HKDF-Expand with the handshake hash as PRK for session keys,
    /// and the static DH secret for the rekey authentication key (PCS).
    ///
    /// # Arguments
    /// * `result` - The handshake result containing the handshake hash
    /// * `static_dh_secret` - The DH(s_initiator, S_responder) shared secret
    pub fn derive(result: &HandshakeResult, static_dh_secret: &[u8; 32]) -> Result<Self, CryptoError> {
        use hkdf::Hkdf;
        use sha2::Sha256;
        use super::rekey::derive_rekey_auth_key;

        let handshake_hash = &result.handshake_hash;

        // HKDF-Expand using SHA-256
        // PRK = handshake_hash (treated as already-extracted key)
        // info = "nomad v1 session keys"
        let label = b"nomad v1 session keys";

        let hk = Hkdf::<Sha256>::from_prk(handshake_hash)
            .map_err(|_| CryptoError::KeyDerivationFailed)?;
        let mut key_material = [0u8; 64];
        hk.expand(label, &mut key_material)
            .map_err(|_| CryptoError::KeyDerivationFailed)?;

        let mut initiator_key = [0u8; SESSION_KEY_SIZE];
        let mut responder_key = [0u8; SESSION_KEY_SIZE];
        initiator_key.copy_from_slice(&key_material[..32]);
        responder_key.copy_from_slice(&key_material[32..]);

        // Derive rekey authentication key from static DH for PCS
        let rekey_auth_key = derive_rekey_auth_key(static_dh_secret);

        // Zeroize the intermediate material
        key_material.zeroize();

        Ok(Self {
            initiator_key: SessionKey::from_bytes(initiator_key),
            responder_key: SessionKey::from_bytes(responder_key),
            handshake_hash: *handshake_hash,
            rekey_auth_key,
        })
    }
}

/// Role in the handshake (affects which key is used for send/receive)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// Initiator (client)
    Initiator,
    /// Responder (server)
    Responder,
}

impl SessionKeys {
    /// Get the send key for the given role.
    pub fn send_key(&self, role: Role) -> &SessionKey {
        match role {
            Role::Initiator => &self.initiator_key,
            Role::Responder => &self.responder_key,
        }
    }

    /// Get the receive key for the given role.
    pub fn recv_key(&self, role: Role) -> &SessionKey {
        match role {
            Role::Initiator => &self.responder_key,
            Role::Responder => &self.initiator_key,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_handshake_roundtrip() {
        // Generate keypairs
        let initiator_keypair = StaticKeypair::generate();
        let responder_keypair = StaticKeypair::generate();

        // Initiator creates handshake with responder's public key
        let mut initiator = InitiatorHandshake::new(
            &initiator_keypair,
            responder_keypair.public_key(),
        ).unwrap();

        // Responder creates handshake
        let mut responder = ResponderHandshake::new(&responder_keypair).unwrap();

        // Initiator sends first message
        let init_payload = b"nomad.echo.v1";
        let init_message = initiator.write_message(init_payload).unwrap();

        // Responder processes first message
        let (recv_payload, remote_public) = responder.read_message(&init_message).unwrap();
        assert_eq!(recv_payload, init_payload);
        assert_eq!(&remote_public, initiator_keypair.public_key());

        // Responder sends response
        let resp_payload = b"OK";
        let (resp_message, responder_result) = responder.write_message(resp_payload).unwrap();

        // Initiator processes response
        let (recv_resp_payload, initiator_result) = initiator.read_message(&resp_message).unwrap();
        assert_eq!(recv_resp_payload, resp_payload);

        // Both should have the same handshake hash
        assert_eq!(initiator_result.handshake_hash, responder_result.handshake_hash);

        // Compute static DH for both parties (should be the same)
        let initiator_static_dh = initiator_keypair.compute_static_dh(responder_keypair.public_key());
        let responder_static_dh = responder_keypair.compute_static_dh(initiator_keypair.public_key());
        assert_eq!(initiator_static_dh, responder_static_dh);

        // Both can derive session keys with static DH
        let initiator_keys = SessionKeys::derive(&initiator_result, &initiator_static_dh).unwrap();
        let responder_keys = SessionKeys::derive(&responder_result, &responder_static_dh).unwrap();

        // Keys should match (initiator's send = responder's receive)
        assert_eq!(
            initiator_keys.send_key(Role::Initiator).as_bytes(),
            responder_keys.recv_key(Role::Responder).as_bytes()
        );
        assert_eq!(
            initiator_keys.recv_key(Role::Initiator).as_bytes(),
            responder_keys.send_key(Role::Responder).as_bytes()
        );

        // Rekey auth keys should also match
        assert_eq!(initiator_keys.rekey_auth_key, responder_keys.rekey_auth_key);
    }

    #[test]
    fn test_handshake_wrong_key_fails() {
        let initiator_keypair = StaticKeypair::generate();
        let responder_keypair = StaticKeypair::generate();
        let wrong_keypair = StaticKeypair::generate();

        // Initiator uses wrong public key
        let mut initiator = InitiatorHandshake::new(
            &initiator_keypair,
            wrong_keypair.public_key(), // Wrong key!
        ).unwrap();

        let mut responder = ResponderHandshake::new(&responder_keypair).unwrap();

        let init_message = initiator.write_message(b"test").unwrap();

        // Responder should fail to decrypt the initiator's static key
        let result = responder.read_message(&init_message);
        assert!(result.is_err());
    }

    #[test]
    fn test_role_keys() {
        let initiator_keypair = StaticKeypair::generate();
        let responder_keypair = StaticKeypair::generate();

        let mut initiator = InitiatorHandshake::new(
            &initiator_keypair,
            responder_keypair.public_key(),
        ).unwrap();
        let mut responder = ResponderHandshake::new(&responder_keypair).unwrap();

        let init_message = initiator.write_message(b"").unwrap();
        responder.read_message(&init_message).unwrap();
        let (resp_message, responder_result) = responder.write_message(b"").unwrap();
        let (_, initiator_result) = initiator.read_message(&resp_message).unwrap();

        // Compute static DH
        let static_dh = initiator_keypair.compute_static_dh(responder_keypair.public_key());

        let initiator_keys = SessionKeys::derive(&initiator_result, &static_dh).unwrap();
        let responder_keys = SessionKeys::derive(&responder_result, &static_dh).unwrap();

        // Verify role-based key access
        assert_eq!(
            initiator_keys.send_key(Role::Initiator).as_bytes(),
            initiator_keys.initiator_key.as_bytes()
        );
        assert_eq!(
            initiator_keys.recv_key(Role::Initiator).as_bytes(),
            initiator_keys.responder_key.as_bytes()
        );
        assert_eq!(
            responder_keys.send_key(Role::Responder).as_bytes(),
            responder_keys.responder_key.as_bytes()
        );
        assert_eq!(
            responder_keys.recv_key(Role::Responder).as_bytes(),
            responder_keys.initiator_key.as_bytes()
        );
    }
}
