//! Error types for NOMAD protocol.

use thiserror::Error;

/// Errors that can occur when applying a diff.
#[derive(Debug, Error, Clone)]
pub enum ApplyError {
    /// Invalid diff format.
    #[error("invalid diff format")]
    InvalidFormat,

    /// Diff version mismatch.
    #[error("diff version mismatch: expected {expected}, got {actual}")]
    VersionMismatch {
        /// Expected version.
        expected: u64,
        /// Actual version.
        actual: u64,
    },

    /// State corruption detected.
    #[error("state corruption detected")]
    StateCorruption,
}

/// Errors that can occur when decoding a diff.
#[derive(Debug, Error, Clone)]
pub enum DecodeError {
    /// Invalid encoding.
    #[error("invalid encoding: {0}")]
    InvalidEncoding(String),

    /// Unexpected end of data.
    #[error("unexpected end of data")]
    UnexpectedEof,

    /// Unsupported version.
    #[error("unsupported version: {0}")]
    UnsupportedVersion(u8),
}

/// Errors in the crypto layer.
#[derive(Debug, Error)]
pub enum CryptoError {
    /// Handshake failed.
    #[error("handshake failed: {0}")]
    HandshakeFailed(String),

    /// AEAD encryption failed.
    #[error("AEAD encryption failed")]
    EncryptionFailed,

    /// AEAD decryption failed (invalid tag or corrupted).
    #[error("AEAD decryption failed (invalid tag or corrupted)")]
    DecryptionFailed,

    /// Nonce counter exhausted - session must terminate.
    #[error("nonce counter exhausted - session must terminate")]
    CounterExhaustion,

    /// Epoch exhausted - session must terminate.
    #[error("epoch exhausted - session must terminate")]
    EpochExhaustion,

    /// Replay detected.
    #[error("replay detected")]
    ReplayDetected,

    /// Key derivation failed.
    #[error("key derivation failed")]
    KeyDerivationFailed,
}

/// Errors in the sync layer.
#[derive(Debug, Error)]
pub enum SyncError {
    /// Apply error.
    #[error("apply error: {0}")]
    Apply(#[from] ApplyError),

    /// Decode error.
    #[error("decode error: {0}")]
    Decode(#[from] DecodeError),
}

/// Top-level NOMAD errors.
#[derive(Debug, Error)]
pub enum NomadError {
    /// Sync error.
    #[error("sync error: {0}")]
    Sync(#[from] SyncError),

    /// Crypto error.
    #[error("crypto error: {0}")]
    Crypto(#[from] CryptoError),

    /// Configuration error.
    #[error("configuration error: {0}")]
    Config(String),

    /// I/O error.
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
}
