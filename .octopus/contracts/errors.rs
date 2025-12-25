// NOMAD Protocol - Error Types Contract
// Tentacles MUST use these error types.

use thiserror::Error;

/// Errors that can occur when applying a diff
#[derive(Debug, Error, Clone)]
pub enum ApplyError {
    #[error("invalid diff format")]
    InvalidFormat,

    #[error("diff version mismatch: expected {expected}, got {actual}")]
    VersionMismatch { expected: u64, actual: u64 },

    #[error("state corruption detected")]
    StateCorruption,
}

/// Errors that can occur when decoding a diff
#[derive(Debug, Error, Clone)]
pub enum DecodeError {
    #[error("invalid encoding: {0}")]
    InvalidEncoding(String),

    #[error("unexpected end of data")]
    UnexpectedEof,

    #[error("unsupported version: {0}")]
    UnsupportedVersion(u8),
}

/// Errors in the crypto layer
#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("handshake failed: {0}")]
    HandshakeFailed(String),

    #[error("AEAD encryption failed")]
    EncryptionFailed,

    #[error("AEAD decryption failed (invalid tag or corrupted)")]
    DecryptionFailed,

    #[error("nonce counter exhausted - session must terminate")]
    CounterExhaustion,

    #[error("epoch exhausted - session must terminate")]
    EpochExhaustion,

    #[error("replay detected")]
    ReplayDetected,

    #[error("key derivation failed")]
    KeyDerivationFailed,
}

/// Errors in the transport layer
#[derive(Debug, Error)]
pub enum TransportError {
    #[error("invalid frame: {0}")]
    InvalidFrame(String),

    #[error("unknown frame type: 0x{0:02x}")]
    UnknownFrameType(u8),

    #[error("session not found: {0:?}")]
    SessionNotFound([u8; 6]),

    #[error("connection timeout")]
    Timeout,

    #[error("connection closed")]
    Closed,

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("crypto error: {0}")]
    Crypto(#[from] CryptoError),
}

/// Errors in the sync layer
#[derive(Debug, Error)]
pub enum SyncError {
    #[error("apply error: {0}")]
    Apply(#[from] ApplyError),

    #[error("decode error: {0}")]
    Decode(#[from] DecodeError),

    #[error("transport error: {0}")]
    Transport(#[from] TransportError),
}

/// Top-level NOMAD errors
#[derive(Debug, Error)]
pub enum NomadError {
    #[error("sync error: {0}")]
    Sync(#[from] SyncError),

    #[error("transport error: {0}")]
    Transport(#[from] TransportError),

    #[error("crypto error: {0}")]
    Crypto(#[from] CryptoError),

    #[error("configuration error: {0}")]
    Config(String),
}
