//! Sync message types
//!
//! Implements the sync message format from 3-SYNC.md contract.

use thiserror::Error;

/// Sync message format (inside encrypted payload)
///
/// Wire format:
/// ```text
/// +0   Sender State Num (8 bytes LE64)
/// +8   Acked State Num (8 bytes LE64)
/// +16  Base State Num (8 bytes LE64)
/// +24  Diff Length (4 bytes LE32)
/// +28  Diff Payload (variable)
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncMessage {
    /// Version of sender's current state
    pub sender_state_num: u64,
    /// Highest version received from peer (acknowledgment)
    pub acked_state_num: u64,
    /// Version this diff was computed from
    pub base_state_num: u64,
    /// Application-specific diff encoding
    pub diff: Vec<u8>,
}

/// Header size in bytes (3 x u64 + u32 = 28)
pub const SYNC_MESSAGE_HEADER_SIZE: usize = 28;

impl SyncMessage {
    /// Create a new sync message
    pub fn new(
        sender_state_num: u64,
        acked_state_num: u64,
        base_state_num: u64,
        diff: Vec<u8>,
    ) -> Self {
        Self {
            sender_state_num,
            acked_state_num,
            base_state_num,
            diff,
        }
    }

    /// Create an ack-only message (empty diff)
    pub fn ack_only(current_version: u64, acked_version: u64) -> Self {
        Self {
            sender_state_num: current_version,
            acked_state_num: acked_version,
            base_state_num: 0,
            diff: Vec::new(),
        }
    }

    /// Check if this is an ack-only message
    pub fn is_ack_only(&self) -> bool {
        self.diff.is_empty()
    }

    /// Total wire size
    pub fn wire_size(&self) -> usize {
        SYNC_MESSAGE_HEADER_SIZE + self.diff.len()
    }

    /// Encode to wire format (28-byte header + diff)
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(self.wire_size());
        buf.extend_from_slice(&self.sender_state_num.to_le_bytes());
        buf.extend_from_slice(&self.acked_state_num.to_le_bytes());
        buf.extend_from_slice(&self.base_state_num.to_le_bytes());
        buf.extend_from_slice(&(self.diff.len() as u32).to_le_bytes());
        buf.extend_from_slice(&self.diff);
        buf
    }

    /// Encode into existing buffer, returns bytes written
    pub fn encode_into(&self, buf: &mut [u8]) -> Result<usize, MessageError> {
        let size = self.wire_size();
        if buf.len() < size {
            return Err(MessageError::BufferTooSmall {
                required: size,
                available: buf.len(),
            });
        }

        buf[0..8].copy_from_slice(&self.sender_state_num.to_le_bytes());
        buf[8..16].copy_from_slice(&self.acked_state_num.to_le_bytes());
        buf[16..24].copy_from_slice(&self.base_state_num.to_le_bytes());
        buf[24..28].copy_from_slice(&(self.diff.len() as u32).to_le_bytes());
        buf[28..size].copy_from_slice(&self.diff);

        Ok(size)
    }

    /// Decode from wire format
    pub fn decode(data: &[u8]) -> Result<Self, MessageError> {
        if data.len() < SYNC_MESSAGE_HEADER_SIZE {
            return Err(MessageError::TooShort {
                expected: SYNC_MESSAGE_HEADER_SIZE,
                actual: data.len(),
            });
        }

        let sender_state_num = u64::from_le_bytes(data[0..8].try_into().unwrap());
        let acked_state_num = u64::from_le_bytes(data[8..16].try_into().unwrap());
        let base_state_num = u64::from_le_bytes(data[16..24].try_into().unwrap());
        let diff_len = u32::from_le_bytes(data[24..28].try_into().unwrap()) as usize;

        if data.len() < SYNC_MESSAGE_HEADER_SIZE + diff_len {
            return Err(MessageError::TooShort {
                expected: SYNC_MESSAGE_HEADER_SIZE + diff_len,
                actual: data.len(),
            });
        }

        let diff = data[SYNC_MESSAGE_HEADER_SIZE..SYNC_MESSAGE_HEADER_SIZE + diff_len].to_vec();

        Ok(Self {
            sender_state_num,
            acked_state_num,
            base_state_num,
            diff,
        })
    }

    /// Decode from wire format, returning message and bytes consumed
    pub fn decode_with_length(data: &[u8]) -> Result<(Self, usize), MessageError> {
        let msg = Self::decode(data)?;
        let consumed = SYNC_MESSAGE_HEADER_SIZE + msg.diff.len();
        Ok((msg, consumed))
    }
}

/// Sync message encoding/decoding errors.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum MessageError {
    /// Input data is shorter than required.
    #[error("message too short: expected {expected} bytes, got {actual}")]
    TooShort {
        /// Minimum bytes required.
        expected: usize,
        /// Actual bytes received.
        actual: usize,
    },

    /// Output buffer is too small to hold encoded data.
    #[error("buffer too small: required {required} bytes, available {available}")]
    BufferTooSmall {
        /// Bytes needed for encoding.
        required: usize,
        /// Bytes available in buffer.
        available: usize,
    },

    /// Message format is invalid or corrupted.
    #[error("invalid format: {0}")]
    InvalidFormat(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_roundtrip() {
        let msg = SyncMessage::new(100, 50, 45, vec![1, 2, 3, 4, 5]);

        let encoded = msg.encode();
        assert_eq!(encoded.len(), SYNC_MESSAGE_HEADER_SIZE + 5);

        let decoded = SyncMessage::decode(&encoded).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn test_ack_only_message() {
        let msg = SyncMessage::ack_only(100, 50);

        assert!(msg.is_ack_only());
        assert_eq!(msg.sender_state_num, 100);
        assert_eq!(msg.acked_state_num, 50);
        assert_eq!(msg.base_state_num, 0);
        assert!(msg.diff.is_empty());

        let encoded = msg.encode();
        assert_eq!(encoded.len(), SYNC_MESSAGE_HEADER_SIZE);
    }

    #[test]
    fn test_decode_too_short() {
        let data = [0u8; 20]; // Less than header size
        let result = SyncMessage::decode(&data);
        assert!(matches!(result, Err(MessageError::TooShort { .. })));
    }

    #[test]
    fn test_decode_diff_truncated() {
        let msg = SyncMessage::new(1, 2, 3, vec![1, 2, 3, 4, 5]);
        let mut encoded = msg.encode();
        encoded.truncate(30); // Cut off some diff bytes

        let result = SyncMessage::decode(&encoded);
        assert!(matches!(result, Err(MessageError::TooShort { .. })));
    }

    #[test]
    fn test_encode_into_buffer() {
        let msg = SyncMessage::new(100, 50, 45, vec![1, 2, 3]);
        let mut buf = [0u8; 100];

        let written = msg.encode_into(&mut buf).unwrap();
        assert_eq!(written, SYNC_MESSAGE_HEADER_SIZE + 3);

        let decoded = SyncMessage::decode(&buf[..written]).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn test_encode_into_small_buffer() {
        let msg = SyncMessage::new(100, 50, 45, vec![1, 2, 3, 4, 5]);
        let mut buf = [0u8; 10]; // Too small

        let result = msg.encode_into(&mut buf);
        assert!(matches!(result, Err(MessageError::BufferTooSmall { .. })));
    }

    #[test]
    fn test_wire_size() {
        let msg = SyncMessage::new(1, 2, 3, vec![0; 100]);
        assert_eq!(msg.wire_size(), SYNC_MESSAGE_HEADER_SIZE + 100);
    }

    #[test]
    fn test_decode_with_length() {
        let msg = SyncMessage::new(10, 20, 30, vec![1, 2, 3]);
        let mut data = msg.encode();
        data.extend_from_slice(&[0xFF; 50]); // Extra trailing data

        let (decoded, consumed) = SyncMessage::decode_with_length(&data).unwrap();
        assert_eq!(decoded, msg);
        assert_eq!(consumed, SYNC_MESSAGE_HEADER_SIZE + 3);
    }
}
