//! XChaCha20-Poly1305 AEAD encryption
//!
//! Per 1-SECURITY.md, all post-handshake frames use XChaCha20-Poly1305.
//! The AAD (Additional Authenticated Data) structure is exactly 16 bytes:
//! - Frame type (1 byte)
//! - Flags (1 byte)
//! - Session ID (6 bytes)
//! - Nonce counter (8 bytes, LE64)

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305, XNonce,
};
use crate::core::{CryptoError, AEAD_NONCE_SIZE, AEAD_TAG_SIZE, SESSION_ID_SIZE};
use zeroize::Zeroize;

/// Size of the session key (32 bytes for XChaCha20)
pub const SESSION_KEY_SIZE: usize = 32;

/// Size of AAD for data frames (type + flags + session_id + nonce_counter)
pub const AAD_SIZE: usize = 16;

/// A session key for AEAD operations.
///
/// Zeroized on drop for security.
#[derive(Clone)]
pub struct SessionKey {
    key: [u8; SESSION_KEY_SIZE],
}

impl SessionKey {
    /// Create a new session key from bytes.
    pub fn from_bytes(key: [u8; SESSION_KEY_SIZE]) -> Self {
        Self { key }
    }

    /// Get the raw key bytes.
    ///
    /// # Security
    /// Handle with care - this exposes sensitive key material.
    pub fn as_bytes(&self) -> &[u8; SESSION_KEY_SIZE] {
        &self.key
    }
}

impl Drop for SessionKey {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

/// Construct AAD (Additional Authenticated Data) for a data frame.
///
/// Layout (exactly 16 bytes):
/// ```text
/// [ frame_type (1) | flags (1) | session_id (6) | nonce_counter (8) ]
/// ```
pub fn construct_aad(
    frame_type: u8,
    flags: u8,
    session_id: &[u8; SESSION_ID_SIZE],
    nonce_counter: u64,
) -> [u8; AAD_SIZE] {
    let mut aad = [0u8; AAD_SIZE];

    aad[0] = frame_type;
    aad[1] = flags;
    aad[2..8].copy_from_slice(session_id);
    aad[8..16].copy_from_slice(&nonce_counter.to_le_bytes());

    aad
}

/// Encrypt plaintext using XChaCha20-Poly1305.
///
/// # Arguments
/// * `key` - 32-byte session key
/// * `nonce` - 24-byte nonce (constructed from epoch, direction, counter)
/// * `aad` - Additional authenticated data
/// * `plaintext` - Data to encrypt
///
/// # Returns
/// Ciphertext with appended 16-byte Poly1305 tag
pub fn encrypt(
    key: &SessionKey,
    nonce: &[u8; AEAD_NONCE_SIZE],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = XChaCha20Poly1305::new(key.as_bytes().into());
    let xnonce = XNonce::from_slice(nonce);

    cipher
        .encrypt(xnonce, chacha20poly1305::aead::Payload { msg: plaintext, aad })
        .map_err(|_| CryptoError::EncryptionFailed)
}

/// Decrypt ciphertext using XChaCha20-Poly1305.
///
/// # Arguments
/// * `key` - 32-byte session key
/// * `nonce` - 24-byte nonce (constructed from epoch, direction, counter)
/// * `aad` - Additional authenticated data
/// * `ciphertext` - Ciphertext with appended 16-byte Poly1305 tag
///
/// # Returns
/// Decrypted plaintext, or error if authentication fails
pub fn decrypt(
    key: &SessionKey,
    nonce: &[u8; AEAD_NONCE_SIZE],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    if ciphertext.len() < AEAD_TAG_SIZE {
        return Err(CryptoError::DecryptionFailed);
    }

    let cipher = XChaCha20Poly1305::new(key.as_bytes().into());
    let xnonce = XNonce::from_slice(nonce);

    cipher
        .decrypt(xnonce, chacha20poly1305::aead::Payload { msg: ciphertext, aad })
        .map_err(|_| CryptoError::DecryptionFailed)
}

/// Encrypt plaintext in-place, appending the tag.
///
/// The buffer must have room for the additional 16-byte tag.
pub fn encrypt_in_place(
    key: &SessionKey,
    nonce: &[u8; AEAD_NONCE_SIZE],
    aad: &[u8],
    buffer: &mut Vec<u8>,
) -> Result<(), CryptoError> {
    let cipher = XChaCha20Poly1305::new(key.as_bytes().into());
    let xnonce = XNonce::from_slice(nonce);

    use chacha20poly1305::aead::AeadInPlace;
    cipher
        .encrypt_in_place(xnonce, aad, buffer)
        .map_err(|_| CryptoError::EncryptionFailed)
}

/// Decrypt ciphertext in-place, removing the tag.
pub fn decrypt_in_place(
    key: &SessionKey,
    nonce: &[u8; AEAD_NONCE_SIZE],
    aad: &[u8],
    buffer: &mut Vec<u8>,
) -> Result<(), CryptoError> {
    if buffer.len() < AEAD_TAG_SIZE {
        return Err(CryptoError::DecryptionFailed);
    }

    let cipher = XChaCha20Poly1305::new(key.as_bytes().into());
    let xnonce = XNonce::from_slice(nonce);

    use chacha20poly1305::aead::AeadInPlace;
    cipher
        .decrypt_in_place(xnonce, aad, buffer)
        .map_err(|_| CryptoError::DecryptionFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aad_construction() {
        let session_id = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
        let aad = construct_aad(0x03, 0x01, &session_id, 42);

        assert_eq!(aad.len(), AAD_SIZE);
        assert_eq!(aad[0], 0x03); // frame type
        assert_eq!(aad[1], 0x01); // flags
        assert_eq!(&aad[2..8], &session_id); // session id
        assert_eq!(&aad[8..16], &42u64.to_le_bytes()); // nonce counter
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = SessionKey::from_bytes([0x42; SESSION_KEY_SIZE]);
        let nonce = [0x01; AEAD_NONCE_SIZE];
        let aad = [0x02; AAD_SIZE];
        let plaintext = b"Hello, NOMAD!";

        let ciphertext = encrypt(&key, &nonce, &aad, plaintext).unwrap();
        assert_eq!(ciphertext.len(), plaintext.len() + AEAD_TAG_SIZE);

        let decrypted = decrypt(&key, &nonce, &aad, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_decrypt_wrong_key_fails() {
        let key1 = SessionKey::from_bytes([0x42; SESSION_KEY_SIZE]);
        let key2 = SessionKey::from_bytes([0x43; SESSION_KEY_SIZE]);
        let nonce = [0x01; AEAD_NONCE_SIZE];
        let aad = [0x02; AAD_SIZE];
        let plaintext = b"Secret message";

        let ciphertext = encrypt(&key1, &nonce, &aad, plaintext).unwrap();
        let result = decrypt(&key2, &nonce, &aad, &ciphertext);

        assert!(matches!(result, Err(CryptoError::DecryptionFailed)));
    }

    #[test]
    fn test_decrypt_wrong_aad_fails() {
        let key = SessionKey::from_bytes([0x42; SESSION_KEY_SIZE]);
        let nonce = [0x01; AEAD_NONCE_SIZE];
        let aad1 = [0x02; AAD_SIZE];
        let aad2 = [0x03; AAD_SIZE];
        let plaintext = b"Secret message";

        let ciphertext = encrypt(&key, &nonce, &aad1, plaintext).unwrap();
        let result = decrypt(&key, &nonce, &aad2, &ciphertext);

        assert!(matches!(result, Err(CryptoError::DecryptionFailed)));
    }

    #[test]
    fn test_decrypt_corrupted_ciphertext_fails() {
        let key = SessionKey::from_bytes([0x42; SESSION_KEY_SIZE]);
        let nonce = [0x01; AEAD_NONCE_SIZE];
        let aad = [0x02; AAD_SIZE];
        let plaintext = b"Secret message";

        let mut ciphertext = encrypt(&key, &nonce, &aad, plaintext).unwrap();
        ciphertext[0] ^= 0xFF; // Corrupt first byte

        let result = decrypt(&key, &nonce, &aad, &ciphertext);
        assert!(matches!(result, Err(CryptoError::DecryptionFailed)));
    }

    #[test]
    fn test_encrypt_decrypt_in_place() {
        let key = SessionKey::from_bytes([0x42; SESSION_KEY_SIZE]);
        let nonce = [0x01; AEAD_NONCE_SIZE];
        let aad = [0x02; AAD_SIZE];
        let plaintext = b"Hello, NOMAD!";

        let mut buffer = plaintext.to_vec();
        encrypt_in_place(&key, &nonce, &aad, &mut buffer).unwrap();
        assert_eq!(buffer.len(), plaintext.len() + AEAD_TAG_SIZE);

        decrypt_in_place(&key, &nonce, &aad, &mut buffer).unwrap();
        assert_eq!(buffer, plaintext);
    }

    #[test]
    fn test_empty_plaintext() {
        let key = SessionKey::from_bytes([0x42; SESSION_KEY_SIZE]);
        let nonce = [0x01; AEAD_NONCE_SIZE];
        let aad = [0x02; AAD_SIZE];
        let plaintext = b"";

        let ciphertext = encrypt(&key, &nonce, &aad, plaintext).unwrap();
        assert_eq!(ciphertext.len(), AEAD_TAG_SIZE); // Just the tag

        let decrypted = decrypt(&key, &nonce, &aad, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }
}
