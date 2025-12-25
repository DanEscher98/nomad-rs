//! Client bootstrap and key exchange.
//!
//! Handles the initial connection setup including:
//! - Key generation or loading
//! - Server public key validation
//! - Noise_IK handshake initiation

use std::net::SocketAddr;

use thiserror::Error;

/// Errors during bootstrap.
#[derive(Debug, Error)]
pub enum BootstrapError {
    /// Invalid server public key.
    #[error("invalid server public key: {0}")]
    InvalidServerKey(String),

    /// Failed to generate client keys.
    #[error("key generation failed: {0}")]
    KeyGenerationFailed(String),

    /// Invalid key format.
    #[error("invalid key format: {0}")]
    InvalidKeyFormat(String),
}

/// Client identity containing the key pair.
#[derive(Clone)]
pub struct ClientIdentity {
    /// Client's static private key (32 bytes).
    private_key: [u8; 32],
    /// Client's static public key (32 bytes).
    public_key: [u8; 32],
}

impl ClientIdentity {
    /// Generate a new random client identity.
    pub fn generate() -> Result<Self, BootstrapError> {
        // TODO: Use nomad-crypto for key generation
        // For now, use random bytes (placeholder)
        use std::time::{SystemTime, UNIX_EPOCH};

        let seed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;

        // Simple PRNG for placeholder (will be replaced with proper crypto)
        let mut private_key = [0u8; 32];
        let mut state = seed;
        for byte in &mut private_key {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            *byte = (state >> 33) as u8;
        }

        // Placeholder public key derivation (will use X25519)
        let public_key = private_key; // TODO: Derive properly

        Ok(Self {
            private_key,
            public_key,
        })
    }

    /// Create identity from an existing private key.
    pub fn from_private_key(private_key: [u8; 32]) -> Result<Self, BootstrapError> {
        // TODO: Derive public key using X25519
        let public_key = private_key; // Placeholder

        Ok(Self {
            private_key,
            public_key,
        })
    }

    /// Get the private key.
    pub fn private_key(&self) -> &[u8; 32] {
        &self.private_key
    }

    /// Get the public key.
    pub fn public_key(&self) -> &[u8; 32] {
        &self.public_key
    }
}

impl std::fmt::Debug for ClientIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientIdentity")
            .field("public_key", &hex_preview(&self.public_key))
            .field("private_key", &"[REDACTED]")
            .finish()
    }
}

/// Server information for connection.
#[derive(Debug, Clone)]
pub struct ServerInfo {
    /// Server address.
    pub addr: SocketAddr,
    /// Server's static public key.
    pub public_key: [u8; 32],
}

impl ServerInfo {
    /// Create new server info.
    pub fn new(addr: SocketAddr, public_key: [u8; 32]) -> Self {
        Self { addr, public_key }
    }

    /// Parse server public key from base64.
    pub fn from_base64_key(addr: SocketAddr, key_base64: &str) -> Result<Self, BootstrapError> {
        let key_bytes = decode_base64(key_base64)
            .map_err(|e| BootstrapError::InvalidServerKey(e.to_string()))?;

        if key_bytes.len() != 32 {
            return Err(BootstrapError::InvalidServerKey(format!(
                "expected 32 bytes, got {}",
                key_bytes.len()
            )));
        }

        let mut public_key = [0u8; 32];
        public_key.copy_from_slice(&key_bytes);

        Ok(Self { addr, public_key })
    }
}

/// Bootstrap configuration.
#[derive(Debug, Clone)]
pub struct BootstrapConfig {
    /// Client identity (optional, generated if not provided).
    pub identity: Option<ClientIdentity>,
    /// Server information.
    pub server: ServerInfo,
    /// State type ID for handshake.
    pub state_type_id: String,
    /// Requested extensions.
    pub extensions: Vec<u16>,
}

/// Result of a successful bootstrap.
#[derive(Debug)]
pub struct BootstrapResult {
    /// Client identity used.
    pub identity: ClientIdentity,
    /// Negotiated extensions.
    pub extensions: Vec<u16>,
    /// Session ID assigned by server.
    pub session_id: [u8; 6],
}

/// Perform client bootstrap.
///
/// This will:
/// 1. Generate or use provided client identity
/// 2. Prepare handshake init message
/// 3. Return bootstrap result for connection
pub fn prepare_bootstrap(config: BootstrapConfig) -> Result<BootstrapResult, BootstrapError> {
    // Get or generate client identity
    let identity = match config.identity {
        Some(id) => id,
        None => ClientIdentity::generate()?,
    };

    // TODO: Actually perform Noise_IK handshake via nomad-crypto
    // For now, return placeholder result

    Ok(BootstrapResult {
        identity,
        extensions: config.extensions,
        session_id: [0u8; 6], // Will be assigned by server
    })
}

// Helper functions

fn hex_preview(bytes: &[u8]) -> String {
    if bytes.len() <= 8 {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    } else {
        format!(
            "{}...",
            bytes[..4].iter().map(|b| format!("{:02x}", b)).collect::<String>()
        )
    }
}

fn decode_base64(input: &str) -> Result<Vec<u8>, BootstrapError> {
    // Simple base64 decode (placeholder implementation)
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let input = input.trim().as_bytes();
    let mut output = Vec::with_capacity(input.len() * 3 / 4);

    let mut buffer = 0u32;
    let mut bits = 0u32;

    for &byte in input {
        if byte == b'=' {
            break;
        }

        let value = ALPHABET
            .iter()
            .position(|&c| c == byte)
            .ok_or_else(|| BootstrapError::InvalidKeyFormat("invalid base64 character".into()))?
            as u32;

        buffer = (buffer << 6) | value;
        bits += 6;

        if bits >= 8 {
            bits -= 8;
            output.push((buffer >> bits) as u8);
            buffer &= (1 << bits) - 1;
        }
    }

    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_identity_generate() {
        let id1 = ClientIdentity::generate().unwrap();
        let id2 = ClientIdentity::generate().unwrap();

        // Keys should be different (with very high probability)
        assert_ne!(id1.private_key(), id2.private_key());
    }

    #[test]
    fn test_base64_decode() {
        // Test basic base64 decoding
        let result = decode_base64("SGVsbG8=").unwrap();
        assert_eq!(result, b"Hello");
    }

    #[test]
    fn test_server_info_from_base64() {
        // 32 zero bytes in base64
        let key_b64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        let addr: SocketAddr = "127.0.0.1:19999".parse().unwrap();

        let server = ServerInfo::from_base64_key(addr, key_b64).unwrap();
        assert_eq!(server.public_key, [0u8; 32]);
    }
}
