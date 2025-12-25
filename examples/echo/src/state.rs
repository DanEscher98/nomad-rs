//! Echo state implementation.
//!
//! Implements the `nomad.echo.v1` state type as specified in CONFORMANCE.md.
//! The echo state is a simple message buffer that can be synchronized
//! between client and server.

use nomad_protocol::core::{ApplyError, DecodeError, SyncState};

/// Maximum message length in bytes.
pub const MAX_MESSAGE_LEN: usize = 1024;

/// Echo state - a simple message that gets echoed back.
///
/// This implements the `nomad.echo.v1` state type for conformance testing.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EchoState {
    /// The message content.
    pub message: Vec<u8>,
    /// Sequence number for ordering.
    pub sequence: u64,
}

impl EchoState {
    /// Create a new empty echo state.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create echo state with a message.
    pub fn with_message(message: impl Into<Vec<u8>>) -> Self {
        Self {
            message: message.into(),
            sequence: 0,
        }
    }

    /// Set the message content.
    pub fn set_message(&mut self, message: impl Into<Vec<u8>>) {
        self.message = message.into();
        self.sequence += 1;
    }

    /// Get the message as a string (lossy conversion).
    pub fn message_str(&self) -> String {
        String::from_utf8_lossy(&self.message).into_owned()
    }
}

/// Diff for echo state - contains the full new message.
///
/// For simplicity, the diff is just the complete new state.
/// This is idempotent: applying the same diff twice has no additional effect.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EchoDiff {
    /// The new message content.
    pub message: Vec<u8>,
    /// The new sequence number.
    pub sequence: u64,
}

impl SyncState for EchoState {
    type Diff = EchoDiff;

    const STATE_TYPE_ID: &'static str = "nomad.echo.v1";

    fn diff_from(&self, _old: &Self) -> Self::Diff {
        // Full state replacement diff (simple but idempotent)
        EchoDiff {
            message: self.message.clone(),
            sequence: self.sequence,
        }
    }

    fn apply_diff(&mut self, diff: &Self::Diff) -> Result<(), ApplyError> {
        // Idempotent: only apply if sequence is newer
        if diff.sequence > self.sequence {
            self.message = diff.message.clone();
            self.sequence = diff.sequence;
        }
        Ok(())
    }

    fn encode_diff(diff: &Self::Diff) -> Vec<u8> {
        // Format: [sequence:8][message_len:2][message:...]
        let mut buf = Vec::with_capacity(10 + diff.message.len());
        buf.extend_from_slice(&diff.sequence.to_le_bytes());
        buf.extend_from_slice(&(diff.message.len() as u16).to_le_bytes());
        buf.extend_from_slice(&diff.message);
        buf
    }

    fn decode_diff(data: &[u8]) -> Result<Self::Diff, DecodeError> {
        if data.len() < 10 {
            return Err(DecodeError::UnexpectedEof);
        }

        let sequence = u64::from_le_bytes(data[0..8].try_into().unwrap());
        let message_len = u16::from_le_bytes(data[8..10].try_into().unwrap()) as usize;

        if data.len() < 10 + message_len {
            return Err(DecodeError::UnexpectedEof);
        }

        if message_len > MAX_MESSAGE_LEN {
            return Err(DecodeError::InvalidEncoding(format!(
                "message too long: {} > {}",
                message_len, MAX_MESSAGE_LEN
            )));
        }

        let message = data[10..10 + message_len].to_vec();

        Ok(EchoDiff { message, sequence })
    }

    fn is_diff_empty(diff: &Self::Diff) -> bool {
        diff.message.is_empty() && diff.sequence == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_echo_state_new() {
        let state = EchoState::new();
        assert!(state.message.is_empty());
        assert_eq!(state.sequence, 0);
    }

    #[test]
    fn test_echo_state_with_message() {
        let state = EchoState::with_message(b"hello".to_vec());
        assert_eq!(state.message, b"hello");
        assert_eq!(state.sequence, 0);
    }

    #[test]
    fn test_set_message_increments_sequence() {
        let mut state = EchoState::new();
        state.set_message(b"first");
        assert_eq!(state.sequence, 1);
        state.set_message(b"second");
        assert_eq!(state.sequence, 2);
    }

    #[test]
    fn test_diff_encode_decode_roundtrip() {
        let diff = EchoDiff {
            message: b"test message".to_vec(),
            sequence: 42,
        };

        let encoded = EchoState::encode_diff(&diff);
        let decoded = EchoState::decode_diff(&encoded).unwrap();

        assert_eq!(diff, decoded);
    }

    #[test]
    fn test_apply_diff_idempotent() {
        let mut state = EchoState::new();
        let diff = EchoDiff {
            message: b"hello".to_vec(),
            sequence: 5,
        };

        // First application
        state.apply_diff(&diff).unwrap();
        assert_eq!(state.message, b"hello");
        assert_eq!(state.sequence, 5);

        // Second application (should be no-op)
        state.apply_diff(&diff).unwrap();
        assert_eq!(state.message, b"hello");
        assert_eq!(state.sequence, 5);
    }

    #[test]
    fn test_apply_diff_ignores_old_sequence() {
        let mut state = EchoState {
            message: b"current".to_vec(),
            sequence: 10,
        };

        let old_diff = EchoDiff {
            message: b"old".to_vec(),
            sequence: 5,
        };

        state.apply_diff(&old_diff).unwrap();
        // Should not change because sequence is older
        assert_eq!(state.message, b"current");
        assert_eq!(state.sequence, 10);
    }

    #[test]
    fn test_state_type_id() {
        assert_eq!(EchoState::STATE_TYPE_ID, "nomad.echo.v1");
    }
}
