//! Frame encoding and decoding for NOMAD transport layer.
//!
//! Implements frame formats from 2-TRANSPORT.md:
//! - Data frame (0x03)
//! - Close frame (0x05)

use thiserror::Error;

/// Size constants from the protocol specification.
pub mod sizes {
    /// AEAD authentication tag size (Poly1305).
    pub const AEAD_TAG_SIZE: usize = 16;
    /// Session ID size (48-bit).
    pub const SESSION_ID_SIZE: usize = 6;
    /// Nonce counter size (64-bit LE).
    pub const NONCE_COUNTER_SIZE: usize = 8;
    /// Data frame header size (type + flags + session_id + nonce).
    pub const DATA_FRAME_HEADER_SIZE: usize = 1 + 1 + SESSION_ID_SIZE + NONCE_COUNTER_SIZE;
    /// Minimum frame size (header + tag, no payload).
    pub const MIN_FRAME_SIZE: usize = DATA_FRAME_HEADER_SIZE + AEAD_TAG_SIZE;
    /// Payload header size (timestamp + echo + length).
    pub const PAYLOAD_HEADER_SIZE: usize = 4 + 4 + 2;
    /// Recommended maximum payload size for mobile networks.
    pub const DEFAULT_MAX_PAYLOAD: usize = 1200;
}

/// Frame type identifiers from 0-PROTOCOL.md.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum FrameType {
    /// Handshake initiation (Noise_IK first message).
    HandshakeInit = 0x01,
    /// Handshake response (Noise_IK second message).
    HandshakeResp = 0x02,
    /// Encrypted data frame.
    Data = 0x03,
    /// Rekey request/response.
    Rekey = 0x04,
    /// Graceful connection close.
    Close = 0x05,
}

impl FrameType {
    /// Parse frame type from a byte.
    pub fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0x01 => Some(Self::HandshakeInit),
            0x02 => Some(Self::HandshakeResp),
            0x03 => Some(Self::Data),
            0x04 => Some(Self::Rekey),
            0x05 => Some(Self::Close),
            _ => None,
        }
    }

    /// Convert frame type to its byte representation.
    pub fn as_byte(self) -> u8 {
        self as u8
    }
}

/// Frame flags for data frames.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FrameFlags(u8);

impl FrameFlags {
    /// No flags set.
    pub const NONE: Self = Self(0);
    /// Frame contains only acknowledgment, no state diff.
    pub const ACK_ONLY: Self = Self(0x01);
    /// Extension data follows payload.
    pub const HAS_EXTENSION: Self = Self(0x02);

    /// Create flags from a raw byte.
    pub fn from_byte(byte: u8) -> Self {
        Self(byte)
    }

    /// Get the raw byte value.
    pub fn as_byte(self) -> u8 {
        self.0
    }

    /// Check if ACK_ONLY flag is set.
    pub fn is_ack_only(self) -> bool {
        self.0 & 0x01 != 0
    }

    /// Check if HAS_EXTENSION flag is set.
    pub fn has_extension(self) -> bool {
        self.0 & 0x02 != 0
    }

    /// Set ACK_ONLY flag.
    pub fn with_ack_only(self) -> Self {
        Self(self.0 | 0x01)
    }

    /// Set HAS_EXTENSION flag.
    pub fn with_extension(self) -> Self {
        Self(self.0 | 0x02)
    }

    /// Check if reserved bits are valid (must be zero).
    pub fn is_valid(self) -> bool {
        self.0 & 0xFC == 0
    }
}

/// Session identifier (6 bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionId([u8; sizes::SESSION_ID_SIZE]);

impl SessionId {
    /// Create a session ID from bytes.
    pub fn from_bytes(bytes: [u8; sizes::SESSION_ID_SIZE]) -> Self {
        Self(bytes)
    }

    /// Get the session ID as bytes.
    pub fn as_bytes(&self) -> &[u8; sizes::SESSION_ID_SIZE] {
        &self.0
    }

    /// Create a zero session ID (for testing).
    pub fn zero() -> Self {
        Self([0u8; sizes::SESSION_ID_SIZE])
    }
}

impl AsRef<[u8]> for SessionId {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Data frame header (unencrypted portion, used as AAD).
///
/// Wire format (16 bytes):
/// ```text
/// +--------+--------+------------------+--------------------+
/// | Type   | Flags  | Session ID       | Nonce Counter      |
/// | 1 byte | 1 byte | 6 bytes          | 8 bytes (LE64)     |
/// +--------+--------+------------------+--------------------+
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DataFrameHeader {
    /// Frame type (should be Data or Close).
    pub frame_type: FrameType,
    /// Frame flags.
    pub flags: FrameFlags,
    /// Session identifier.
    pub session_id: SessionId,
    /// Nonce counter (per-direction, monotonically increasing).
    pub nonce_counter: u64,
}

impl DataFrameHeader {
    /// Create a new data frame header.
    pub fn new(session_id: SessionId, nonce_counter: u64) -> Self {
        Self {
            frame_type: FrameType::Data,
            flags: FrameFlags::NONE,
            session_id,
            nonce_counter,
        }
    }

    /// Create a close frame header.
    pub fn close(session_id: SessionId, nonce_counter: u64) -> Self {
        Self {
            frame_type: FrameType::Close,
            flags: FrameFlags::NONE,
            session_id,
            nonce_counter,
        }
    }

    /// Serialize header to bytes (16 bytes).
    pub fn to_bytes(&self) -> [u8; sizes::DATA_FRAME_HEADER_SIZE] {
        let mut buf = [0u8; sizes::DATA_FRAME_HEADER_SIZE];
        buf[0] = self.frame_type.as_byte();
        buf[1] = self.flags.as_byte();
        buf[2..8].copy_from_slice(self.session_id.as_bytes());
        buf[8..16].copy_from_slice(&self.nonce_counter.to_le_bytes());
        buf
    }

    /// Parse header from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, FrameError> {
        if bytes.len() < sizes::DATA_FRAME_HEADER_SIZE {
            return Err(FrameError::TooShort {
                expected: sizes::DATA_FRAME_HEADER_SIZE,
                actual: bytes.len(),
            });
        }

        let frame_type = FrameType::from_byte(bytes[0]).ok_or(FrameError::InvalidType(bytes[0]))?;

        let flags = FrameFlags::from_byte(bytes[1]);
        if !flags.is_valid() {
            return Err(FrameError::InvalidFlags(bytes[1]));
        }

        let mut session_id_bytes = [0u8; sizes::SESSION_ID_SIZE];
        session_id_bytes.copy_from_slice(&bytes[2..8]);
        let session_id = SessionId::from_bytes(session_id_bytes);

        let mut nonce_bytes = [0u8; 8];
        nonce_bytes.copy_from_slice(&bytes[8..16]);
        let nonce_counter = u64::from_le_bytes(nonce_bytes);

        Ok(Self {
            frame_type,
            flags,
            session_id,
            nonce_counter,
        })
    }
}

/// Payload header (inside encrypted portion).
///
/// Wire format (10 bytes):
/// ```text
/// +------------------+--------------------+------------------+
/// | Timestamp        | Timestamp Echo     | Payload Length   |
/// | 4 bytes (LE32)   | 4 bytes (LE32)     | 2 bytes (LE16)   |
/// +------------------+--------------------+------------------+
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PayloadHeader {
    /// Sender's current time in ms since session start.
    pub timestamp: u32,
    /// Most recent timestamp received from peer (0 if none).
    pub timestamp_echo: u32,
    /// Length of the sync message that follows.
    pub payload_length: u16,
}

impl PayloadHeader {
    /// Create a new payload header.
    pub fn new(timestamp: u32, timestamp_echo: u32, payload_length: u16) -> Self {
        Self {
            timestamp,
            timestamp_echo,
            payload_length,
        }
    }

    /// Serialize to bytes (10 bytes).
    pub fn to_bytes(&self) -> [u8; sizes::PAYLOAD_HEADER_SIZE] {
        let mut buf = [0u8; sizes::PAYLOAD_HEADER_SIZE];
        buf[0..4].copy_from_slice(&self.timestamp.to_le_bytes());
        buf[4..8].copy_from_slice(&self.timestamp_echo.to_le_bytes());
        buf[8..10].copy_from_slice(&self.payload_length.to_le_bytes());
        buf
    }

    /// Parse from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, FrameError> {
        if bytes.len() < sizes::PAYLOAD_HEADER_SIZE {
            return Err(FrameError::TooShort {
                expected: sizes::PAYLOAD_HEADER_SIZE,
                actual: bytes.len(),
            });
        }

        let timestamp = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let timestamp_echo = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        let payload_length = u16::from_le_bytes([bytes[8], bytes[9]]);

        Ok(Self {
            timestamp,
            timestamp_echo,
            payload_length,
        })
    }
}

/// A complete data frame ready for encryption/transmission.
#[derive(Debug, Clone)]
pub struct DataFrame {
    /// The unencrypted header (used as AAD).
    pub header: DataFrameHeader,
    /// The payload header (will be encrypted).
    pub payload_header: PayloadHeader,
    /// The sync message (will be encrypted).
    pub sync_message: Vec<u8>,
}

impl DataFrame {
    /// Create a new data frame.
    pub fn new(
        session_id: SessionId,
        nonce_counter: u64,
        timestamp: u32,
        timestamp_echo: u32,
        sync_message: Vec<u8>,
    ) -> Self {
        let payload_length = sync_message.len() as u16;
        Self {
            header: DataFrameHeader::new(session_id, nonce_counter),
            payload_header: PayloadHeader::new(timestamp, timestamp_echo, payload_length),
            sync_message,
        }
    }

    /// Create an ACK-only frame (keepalive or pure acknowledgment).
    pub fn ack_only(
        session_id: SessionId,
        nonce_counter: u64,
        timestamp: u32,
        timestamp_echo: u32,
    ) -> Self {
        let mut frame = Self::new(session_id, nonce_counter, timestamp, timestamp_echo, vec![]);
        frame.header.flags = FrameFlags::ACK_ONLY;
        frame
    }

    /// Get the plaintext that will be encrypted.
    pub fn plaintext(&self) -> Vec<u8> {
        let mut plaintext =
            Vec::with_capacity(sizes::PAYLOAD_HEADER_SIZE + self.sync_message.len());
        plaintext.extend_from_slice(&self.payload_header.to_bytes());
        plaintext.extend_from_slice(&self.sync_message);
        plaintext
    }

    /// Get the AAD (Additional Authenticated Data) - the frame header.
    pub fn aad(&self) -> [u8; sizes::DATA_FRAME_HEADER_SIZE] {
        self.header.to_bytes()
    }
}

/// A close frame for graceful termination.
#[derive(Debug, Clone, Copy)]
pub struct CloseFrame {
    /// The frame header.
    pub header: DataFrameHeader,
    /// Highest state version acknowledged (encrypted).
    pub final_ack: u64,
}

impl CloseFrame {
    /// Create a new close frame.
    pub fn new(session_id: SessionId, nonce_counter: u64, final_ack: u64) -> Self {
        Self {
            header: DataFrameHeader::close(session_id, nonce_counter),
            final_ack,
        }
    }

    /// Get the plaintext that will be encrypted.
    pub fn plaintext(&self) -> [u8; 8] {
        self.final_ack.to_le_bytes()
    }

    /// Get the AAD.
    pub fn aad(&self) -> [u8; sizes::DATA_FRAME_HEADER_SIZE] {
        self.header.to_bytes()
    }
}

/// Errors that can occur during frame parsing.
#[derive(Debug, Error)]
pub enum FrameError {
    /// Frame is too short.
    #[error("frame too short: expected at least {expected} bytes, got {actual}")]
    TooShort {
        /// Minimum expected size.
        expected: usize,
        /// Actual size received.
        actual: usize,
    },

    /// Invalid frame type.
    #[error("invalid frame type: 0x{0:02x}")]
    InvalidType(u8),

    /// Invalid flags (reserved bits set).
    #[error("invalid flags: 0x{0:02x} (reserved bits must be 0)")]
    InvalidFlags(u8),

    /// Payload length mismatch.
    #[error("payload length mismatch: header says {expected}, but {actual} bytes available")]
    PayloadLengthMismatch {
        /// Expected payload length from header.
        expected: usize,
        /// Actual bytes available.
        actual: usize,
    },
}

/// Parse a received frame to determine its type and extract the header.
///
/// This only parses the unencrypted header. The payload must be decrypted
/// before parsing the payload header.
pub fn parse_frame_header(data: &[u8]) -> Result<DataFrameHeader, FrameError> {
    if data.len() < sizes::MIN_FRAME_SIZE {
        return Err(FrameError::TooShort {
            expected: sizes::MIN_FRAME_SIZE,
            actual: data.len(),
        });
    }
    DataFrameHeader::from_bytes(data)
}

/// Parse a decrypted payload to extract the payload header and sync message.
pub fn parse_payload(data: &[u8]) -> Result<(PayloadHeader, &[u8]), FrameError> {
    let header = PayloadHeader::from_bytes(data)?;
    let sync_start = sizes::PAYLOAD_HEADER_SIZE;
    let sync_end = sync_start + header.payload_length as usize;

    if data.len() < sync_end {
        return Err(FrameError::PayloadLengthMismatch {
            expected: header.payload_length as usize,
            actual: data.len() - sizes::PAYLOAD_HEADER_SIZE,
        });
    }

    Ok((header, &data[sync_start..sync_end]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_frame_type_roundtrip() {
        for t in [
            FrameType::HandshakeInit,
            FrameType::HandshakeResp,
            FrameType::Data,
            FrameType::Rekey,
            FrameType::Close,
        ] {
            assert_eq!(FrameType::from_byte(t.as_byte()), Some(t));
        }
        assert_eq!(FrameType::from_byte(0x00), None);
        assert_eq!(FrameType::from_byte(0xFF), None);
    }

    #[test]
    fn test_frame_flags() {
        let flags = FrameFlags::NONE;
        assert!(!flags.is_ack_only());
        assert!(!flags.has_extension());
        assert!(flags.is_valid());

        let flags = FrameFlags::ACK_ONLY;
        assert!(flags.is_ack_only());
        assert!(!flags.has_extension());
        assert!(flags.is_valid());

        let flags = FrameFlags::NONE.with_ack_only().with_extension();
        assert!(flags.is_ack_only());
        assert!(flags.has_extension());
        assert!(flags.is_valid());

        // Reserved bits must be zero
        let invalid = FrameFlags::from_byte(0x04);
        assert!(!invalid.is_valid());
    }

    #[test]
    fn test_session_id() {
        let id = SessionId::from_bytes([0x01, 0x02, 0x03, 0x04, 0x05, 0x06]);
        assert_eq!(id.as_bytes(), &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06]);
    }

    #[test]
    fn test_data_frame_header_roundtrip() {
        let header = DataFrameHeader {
            frame_type: FrameType::Data,
            flags: FrameFlags::ACK_ONLY,
            session_id: SessionId::from_bytes([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]),
            nonce_counter: 0x123456789ABCDEF0,
        };

        let bytes = header.to_bytes();
        assert_eq!(bytes.len(), sizes::DATA_FRAME_HEADER_SIZE);

        let parsed = DataFrameHeader::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.frame_type, header.frame_type);
        assert_eq!(parsed.flags, header.flags);
        assert_eq!(parsed.session_id, header.session_id);
        assert_eq!(parsed.nonce_counter, header.nonce_counter);
    }

    #[test]
    fn test_payload_header_roundtrip() {
        let header = PayloadHeader {
            timestamp: 0x12345678,
            timestamp_echo: 0xABCDEF01,
            payload_length: 256,
        };

        let bytes = header.to_bytes();
        assert_eq!(bytes.len(), sizes::PAYLOAD_HEADER_SIZE);

        let parsed = PayloadHeader::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.timestamp, header.timestamp);
        assert_eq!(parsed.timestamp_echo, header.timestamp_echo);
        assert_eq!(parsed.payload_length, header.payload_length);
    }

    #[test]
    fn test_data_frame_plaintext() {
        let frame = DataFrame::new(
            SessionId::zero(),
            1,
            1000,
            500,
            vec![0x01, 0x02, 0x03, 0x04],
        );

        let plaintext = frame.plaintext();
        // Payload header (10 bytes) + sync message (4 bytes) = 14 bytes
        assert_eq!(plaintext.len(), sizes::PAYLOAD_HEADER_SIZE + 4);
    }

    #[test]
    fn test_ack_only_frame() {
        let frame = DataFrame::ack_only(SessionId::zero(), 1, 1000, 500);

        assert!(frame.header.flags.is_ack_only());
        assert!(frame.sync_message.is_empty());
        assert_eq!(frame.payload_header.payload_length, 0);
    }

    #[test]
    fn test_close_frame() {
        let frame = CloseFrame::new(SessionId::zero(), 100, 12345);

        assert_eq!(frame.header.frame_type, FrameType::Close);
        assert_eq!(frame.final_ack, 12345);

        let plaintext = frame.plaintext();
        assert_eq!(plaintext, 12345u64.to_le_bytes());
    }

    #[test]
    fn test_parse_too_short() {
        let data = [0u8; 10]; // Less than MIN_FRAME_SIZE
        assert!(matches!(
            parse_frame_header(&data),
            Err(FrameError::TooShort { .. })
        ));
    }

    #[test]
    fn test_parse_invalid_type() {
        let mut data = [0u8; sizes::MIN_FRAME_SIZE];
        data[0] = 0xFF; // Invalid frame type
        assert!(matches!(
            parse_frame_header(&data),
            Err(FrameError::InvalidType(0xFF))
        ));
    }
}
