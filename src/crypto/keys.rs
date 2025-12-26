//! X25519 key management
//!
//! Provides secure key generation and handling for the NOMAD protocol.

use crate::core::{PRIVATE_KEY_SIZE, PUBLIC_KEY_SIZE, SESSION_ID_SIZE};
use rand::{rngs::OsRng, RngCore};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

/// A static X25519 keypair for long-term identity.
///
/// The private key is zeroized on drop for security.
#[derive(Clone)]
pub struct StaticKeypair {
    /// Private key (32 bytes) - zeroized on drop
    private: [u8; PRIVATE_KEY_SIZE],
    /// Public key (32 bytes)
    public: [u8; PUBLIC_KEY_SIZE],
}

impl StaticKeypair {
    /// Generate a new random keypair.
    pub fn generate() -> Self {
        // Use snow's keypair generation for proper X25519 keys
        let builder = snow::Builder::new("Noise_IK_25519_ChaChaPoly_BLAKE2s".parse().unwrap());
        let keypair = builder.generate_keypair().unwrap();

        let mut private_key = [0u8; PRIVATE_KEY_SIZE];
        let mut public_key = [0u8; PUBLIC_KEY_SIZE];
        private_key.copy_from_slice(&keypair.private);
        public_key.copy_from_slice(&keypair.public);

        Self {
            private: private_key,
            public: public_key,
        }
    }

    /// Create a keypair from existing key material.
    ///
    /// # Safety
    /// The caller must ensure the private key is valid X25519 key material.
    pub fn from_bytes(private: [u8; PRIVATE_KEY_SIZE], public: [u8; PUBLIC_KEY_SIZE]) -> Self {
        Self { private, public }
    }

    /// Get the public key.
    pub fn public_key(&self) -> &[u8; PUBLIC_KEY_SIZE] {
        &self.public
    }

    /// Get the private key.
    ///
    /// # Security
    /// Handle with care - this exposes sensitive key material.
    pub fn private_key(&self) -> &[u8; PRIVATE_KEY_SIZE] {
        &self.private
    }

    /// Compute the static DH shared secret with a remote public key.
    ///
    /// This computes DH(our_static, their_static) which is used for
    /// deriving the rekey authentication key for PCS.
    ///
    /// # Arguments
    /// * `remote_public` - The remote party's static public key
    ///
    /// # Returns
    /// The 32-byte shared secret
    pub fn compute_static_dh(&self, remote_public: &[u8; PUBLIC_KEY_SIZE]) -> [u8; 32] {
        let secret = StaticSecret::from(self.private);
        let public = PublicKey::from(*remote_public);
        let shared = secret.diffie_hellman(&public);
        *shared.as_bytes()
    }
}

impl Drop for StaticKeypair {
    fn drop(&mut self) {
        self.private.zeroize();
    }
}

/// Session ID - 48-bit random identifier for session demultiplexing.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SessionId(pub [u8; SESSION_ID_SIZE]);

impl SessionId {
    /// Generate a new random session ID.
    pub fn generate() -> Self {
        let mut id = [0u8; SESSION_ID_SIZE];
        OsRng.fill_bytes(&mut id);
        Self(id)
    }

    /// Create from raw bytes.
    pub fn from_bytes(bytes: [u8; SESSION_ID_SIZE]) -> Self {
        Self(bytes)
    }

    /// Get the raw bytes.
    pub fn as_bytes(&self) -> &[u8; SESSION_ID_SIZE] {
        &self.0
    }
}

impl AsRef<[u8]> for SessionId {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let kp1 = StaticKeypair::generate();
        let kp2 = StaticKeypair::generate();

        // Keys should be different
        assert_ne!(kp1.public_key(), kp2.public_key());
        assert_ne!(kp1.private_key(), kp2.private_key());

        // Keys should be correct size
        assert_eq!(kp1.public_key().len(), PUBLIC_KEY_SIZE);
        assert_eq!(kp1.private_key().len(), PRIVATE_KEY_SIZE);
    }

    #[test]
    fn test_session_id_generation() {
        let id1 = SessionId::generate();
        let id2 = SessionId::generate();

        // IDs should be different (with overwhelming probability)
        assert_ne!(id1, id2);
        assert_eq!(id1.as_bytes().len(), SESSION_ID_SIZE);
    }

    #[test]
    fn test_session_id_from_bytes() {
        let bytes = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
        let id = SessionId::from_bytes(bytes);
        assert_eq!(id.as_bytes(), &bytes);
    }
}
