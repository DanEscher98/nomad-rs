//! Transport layer error types.
//!
//! All errors in this module are designed for silent dropping per the spec:
//! "Silent drops prevent confirmation of session existence to attackers."

use std::io;

use thiserror::Error;

use super::frame::FrameError;

/// Transport layer errors.
#[derive(Debug, Error)]
pub enum TransportError {
    /// Frame parsing error.
    #[error("frame error: {0}")]
    Frame(#[from] FrameError),

    /// I/O error (socket operations).
    #[error("i/o error: {0}")]
    Io(#[from] io::Error),

    /// Invalid AEAD tag - frame authentication failed.
    /// Per spec: silently drop, do not respond.
    #[error("authentication failed")]
    AuthenticationFailed,

    /// Unknown session ID.
    /// Per spec: silently drop to prevent session enumeration.
    #[error("unknown session")]
    UnknownSession,

    /// Nonce replay detected.
    /// Per spec: silently drop to prevent replay attacks.
    #[error("nonce replay detected")]
    NonceReplay,

    /// Nonce too old (outside anti-replay window).
    /// Per spec: silently drop.
    #[error("nonce too old")]
    NonceTooOld,

    /// Frame too small to be valid.
    /// Per spec: silently drop to prevent parsing exploits.
    #[error("frame too small")]
    FrameTooSmall,

    /// Connection has timed out.
    #[error("connection timeout")]
    ConnectionTimeout,

    /// Too many retransmissions, connection failed.
    #[error("max retransmits exceeded")]
    MaxRetransmitsExceeded,

    /// Connection is closed.
    #[error("connection closed")]
    ConnectionClosed,

    /// Anti-amplification limit reached.
    #[error("amplification limit reached")]
    AmplificationLimit,

    /// Migration rate limited.
    #[error("migration rate limited")]
    MigrationRateLimited,

    /// Counter exhaustion - nonce counter overflow.
    /// This is a critical security error requiring session termination.
    #[error("nonce counter exhaustion - session must be terminated")]
    CounterExhaustion,
}

impl TransportError {
    /// Check if this error should result in silent drop (no response sent).
    ///
    /// Per 2-TRANSPORT.md, these errors should not generate any response
    /// to prevent information leakage to attackers.
    pub fn is_silent_drop(&self) -> bool {
        matches!(
            self,
            TransportError::AuthenticationFailed
                | TransportError::UnknownSession
                | TransportError::NonceReplay
                | TransportError::NonceTooOld
                | TransportError::FrameTooSmall
        )
    }

    /// Check if this error is fatal to the connection.
    pub fn is_fatal(&self) -> bool {
        matches!(
            self,
            TransportError::ConnectionTimeout
                | TransportError::MaxRetransmitsExceeded
                | TransportError::ConnectionClosed
                | TransportError::CounterExhaustion
        )
    }

    /// Check if this error is a security-related error.
    pub fn is_security_error(&self) -> bool {
        matches!(
            self,
            TransportError::AuthenticationFailed
                | TransportError::NonceReplay
                | TransportError::NonceTooOld
                | TransportError::CounterExhaustion
        )
    }
}

/// Result type for transport operations.
pub type TransportResult<T> = Result<T, TransportError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_silent_drop_errors() {
        assert!(TransportError::AuthenticationFailed.is_silent_drop());
        assert!(TransportError::UnknownSession.is_silent_drop());
        assert!(TransportError::NonceReplay.is_silent_drop());
        assert!(TransportError::NonceTooOld.is_silent_drop());
        assert!(TransportError::FrameTooSmall.is_silent_drop());

        assert!(!TransportError::ConnectionTimeout.is_silent_drop());
        assert!(!TransportError::Io(io::Error::new(io::ErrorKind::Other, "test")).is_silent_drop());
    }

    #[test]
    fn test_fatal_errors() {
        assert!(TransportError::ConnectionTimeout.is_fatal());
        assert!(TransportError::MaxRetransmitsExceeded.is_fatal());
        assert!(TransportError::ConnectionClosed.is_fatal());
        assert!(TransportError::CounterExhaustion.is_fatal());

        assert!(!TransportError::AuthenticationFailed.is_fatal());
        assert!(!TransportError::NonceReplay.is_fatal());
    }

    #[test]
    fn test_security_errors() {
        assert!(TransportError::AuthenticationFailed.is_security_error());
        assert!(TransportError::NonceReplay.is_security_error());
        assert!(TransportError::NonceTooOld.is_security_error());
        assert!(TransportError::CounterExhaustion.is_security_error());

        assert!(!TransportError::ConnectionTimeout.is_security_error());
        assert!(!TransportError::AmplificationLimit.is_security_error());
    }
}
