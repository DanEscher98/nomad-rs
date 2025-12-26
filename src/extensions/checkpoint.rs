//! Checkpoint extension (0x0006)
//!
//! Provides full state snapshots for recovery, initial sync, or periodic
//! consistency verification. Unlike incremental sync, checkpoints contain
//! the complete state at a specific point in time.
//!
//! Wire format for extension negotiation:
//! ```text
//! +0  Flags (1 byte)
//!     - bit 0: Client can request checkpoints
//!     - bit 1: Server sends periodic checkpoints
//!     - bit 2: Incremental checkpoints supported (delta from previous)
//!     - bit 3: Compressed checkpoints supported
//! +1  Max checkpoint size (4 bytes LE32) - maximum uncompressed size
//! +5  Checkpoint interval hint (2 bytes LE16) - suggested seconds between checkpoints
//! ```
//!
//! Wire format for checkpoint frame:
//! ```text
//! +0   Checkpoint ID (8 bytes LE64)
//! +8   Flags (1 byte)
//!      - bit 0: Is compressed
//!      - bit 1: Is incremental (delta from base_id)
//!      - bit 2: Has signature
//! +9   State number (8 bytes LE64) - sync state this checkpoint represents
//! +17  Base checkpoint ID (8 bytes LE64) - for incremental, 0 otherwise
//! +25  Uncompressed size (4 bytes LE32)
//! +29  Payload length (4 bytes LE32)
//! +33  Payload data
//! +N   [Optional] Signature (32 bytes) if Has signature flag set
//! ```

use super::negotiation::{ext_type, Extension, NegotiationError};

/// Checkpoint negotiation flags
pub mod checkpoint_config_flags {
    /// Client can request checkpoints on demand
    pub const CLIENT_REQUEST: u8 = 0x01;
    /// Server sends periodic checkpoints
    pub const PERIODIC: u8 = 0x02;
    /// Incremental checkpoints (delta from base) supported
    pub const INCREMENTAL: u8 = 0x04;
    /// Compressed checkpoints supported
    pub const COMPRESSED: u8 = 0x08;
}

/// Checkpoint frame flags
pub mod checkpoint_frame_flags {
    /// Payload is compressed
    pub const COMPRESSED: u8 = 0x01;
    /// Checkpoint is incremental (delta from base)
    pub const INCREMENTAL: u8 = 0x02;
    /// Frame includes signature
    pub const SIGNED: u8 = 0x04;
}

/// Checkpoint configuration
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckpointConfig {
    /// Feature flags
    pub flags: u8,
    /// Maximum uncompressed checkpoint size
    pub max_size: u32,
    /// Suggested interval between checkpoints (seconds)
    pub interval_secs: u16,
}

impl Default for CheckpointConfig {
    fn default() -> Self {
        Self {
            flags: checkpoint_config_flags::CLIENT_REQUEST | checkpoint_config_flags::COMPRESSED,
            max_size: 16 * 1024 * 1024, // 16 MB
            interval_secs: 300,          // 5 minutes
        }
    }
}

impl CheckpointConfig {
    /// Create config with all features
    pub fn full() -> Self {
        Self {
            flags: checkpoint_config_flags::CLIENT_REQUEST
                | checkpoint_config_flags::PERIODIC
                | checkpoint_config_flags::INCREMENTAL
                | checkpoint_config_flags::COMPRESSED,
            max_size: 64 * 1024 * 1024, // 64 MB
            interval_secs: 60,
        }
    }

    /// Check if client can request checkpoints
    pub fn supports_client_request(&self) -> bool {
        (self.flags & checkpoint_config_flags::CLIENT_REQUEST) != 0
    }

    /// Check if server sends periodic checkpoints
    pub fn supports_periodic(&self) -> bool {
        (self.flags & checkpoint_config_flags::PERIODIC) != 0
    }

    /// Check if incremental checkpoints are supported
    pub fn supports_incremental(&self) -> bool {
        (self.flags & checkpoint_config_flags::INCREMENTAL) != 0
    }

    /// Check if compressed checkpoints are supported
    pub fn supports_compressed(&self) -> bool {
        (self.flags & checkpoint_config_flags::COMPRESSED) != 0
    }

    /// Wire size
    pub const fn wire_size() -> usize {
        7 // flags(1) + max_size(4) + interval(2)
    }

    /// Encode to extension
    pub fn to_extension(&self) -> Extension {
        let mut data = Vec::with_capacity(Self::wire_size());
        data.push(self.flags);
        data.extend_from_slice(&self.max_size.to_le_bytes());
        data.extend_from_slice(&self.interval_secs.to_le_bytes());
        Extension::new(ext_type::CHECKPOINT, data)
    }

    /// Decode from extension
    pub fn from_extension(ext: &Extension) -> Option<Self> {
        if ext.ext_type != ext_type::CHECKPOINT || ext.data.len() < Self::wire_size() {
            return None;
        }
        Some(Self {
            flags: ext.data[0],
            max_size: u32::from_le_bytes([ext.data[1], ext.data[2], ext.data[3], ext.data[4]]),
            interval_secs: u16::from_le_bytes([ext.data[5], ext.data[6]]),
        })
    }

    /// Negotiate between client and server
    pub fn negotiate(client: &Self, server: &Self) -> Self {
        Self {
            flags: client.flags & server.flags,
            max_size: client.max_size.min(server.max_size),
            interval_secs: client.interval_secs.max(server.interval_secs), // Use longer interval
        }
    }
}

/// Header for a checkpoint frame
pub const CHECKPOINT_HEADER_SIZE: usize = 33;

/// A checkpoint frame header
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckpointHeader {
    /// Unique checkpoint identifier
    pub checkpoint_id: u64,
    /// Frame flags
    pub flags: u8,
    /// State number this checkpoint represents
    pub state_num: u64,
    /// Base checkpoint ID for incremental (0 if full)
    pub base_id: u64,
    /// Uncompressed payload size
    pub uncompressed_size: u32,
    /// Actual payload size in frame
    pub payload_len: u32,
}

impl CheckpointHeader {
    /// Create a full checkpoint header
    pub fn full(checkpoint_id: u64, state_num: u64, size: u32) -> Self {
        Self {
            checkpoint_id,
            flags: 0,
            state_num,
            base_id: 0,
            uncompressed_size: size,
            payload_len: size,
        }
    }

    /// Create an incremental checkpoint header
    pub fn incremental(checkpoint_id: u64, state_num: u64, base_id: u64, size: u32) -> Self {
        Self {
            checkpoint_id,
            flags: checkpoint_frame_flags::INCREMENTAL,
            state_num,
            base_id,
            uncompressed_size: size,
            payload_len: size,
        }
    }

    /// Check if checkpoint is compressed
    pub fn is_compressed(&self) -> bool {
        (self.flags & checkpoint_frame_flags::COMPRESSED) != 0
    }

    /// Check if checkpoint is incremental
    pub fn is_incremental(&self) -> bool {
        (self.flags & checkpoint_frame_flags::INCREMENTAL) != 0
    }

    /// Check if checkpoint has signature
    pub fn is_signed(&self) -> bool {
        (self.flags & checkpoint_frame_flags::SIGNED) != 0
    }

    /// Set compressed flag and actual payload size
    pub fn set_compressed(&mut self, compressed_len: u32) {
        self.flags |= checkpoint_frame_flags::COMPRESSED;
        self.payload_len = compressed_len;
    }

    /// Set signed flag
    pub fn set_signed(&mut self) {
        self.flags |= checkpoint_frame_flags::SIGNED;
    }

    /// Encode header to bytes
    pub fn encode(&self) -> [u8; CHECKPOINT_HEADER_SIZE] {
        let mut buf = [0u8; CHECKPOINT_HEADER_SIZE];
        buf[0..8].copy_from_slice(&self.checkpoint_id.to_le_bytes());
        buf[8] = self.flags;
        buf[9..17].copy_from_slice(&self.state_num.to_le_bytes());
        buf[17..25].copy_from_slice(&self.base_id.to_le_bytes());
        buf[25..29].copy_from_slice(&self.uncompressed_size.to_le_bytes());
        buf[29..33].copy_from_slice(&self.payload_len.to_le_bytes());
        buf
    }

    /// Decode header from bytes
    pub fn decode(data: &[u8]) -> Result<Self, NegotiationError> {
        if data.len() < CHECKPOINT_HEADER_SIZE {
            return Err(NegotiationError::TooShort {
                expected: CHECKPOINT_HEADER_SIZE,
                actual: data.len(),
            });
        }

        Ok(Self {
            checkpoint_id: u64::from_le_bytes(
                data[0..8].try_into().expect("length checked"),
            ),
            flags: data[8],
            state_num: u64::from_le_bytes(data[9..17].try_into().expect("length checked")),
            base_id: u64::from_le_bytes(data[17..25].try_into().expect("length checked")),
            uncompressed_size: u32::from_le_bytes(
                data[25..29].try_into().expect("length checked"),
            ),
            payload_len: u32::from_le_bytes(data[29..33].try_into().expect("length checked")),
        })
    }
}

/// A complete checkpoint (header + payload)
#[derive(Debug, Clone)]
pub struct Checkpoint {
    /// Checkpoint header
    pub header: CheckpointHeader,
    /// Checkpoint payload (may be compressed)
    pub payload: Vec<u8>,
    /// Optional signature
    pub signature: Option<[u8; 32]>,
}

impl Checkpoint {
    /// Create a full checkpoint
    pub fn new(checkpoint_id: u64, state_num: u64, data: Vec<u8>) -> Self {
        let header = CheckpointHeader::full(checkpoint_id, state_num, data.len() as u32);
        Self {
            header,
            payload: data,
            signature: None,
        }
    }

    /// Total wire size
    pub fn wire_size(&self) -> usize {
        CHECKPOINT_HEADER_SIZE
            + self.payload.len()
            + if self.signature.is_some() { 32 } else { 0 }
    }

    /// Encode to bytes
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(self.wire_size());
        buf.extend_from_slice(&self.header.encode());
        buf.extend_from_slice(&self.payload);
        if let Some(sig) = &self.signature {
            buf.extend_from_slice(sig);
        }
        buf
    }

    /// Decode from bytes
    pub fn decode(data: &[u8]) -> Result<Self, NegotiationError> {
        let header = CheckpointHeader::decode(data)?;

        let payload_start = CHECKPOINT_HEADER_SIZE;
        let payload_end = payload_start + header.payload_len as usize;

        if data.len() < payload_end {
            return Err(NegotiationError::TooShort {
                expected: payload_end,
                actual: data.len(),
            });
        }

        let payload = data[payload_start..payload_end].to_vec();

        let signature = if header.is_signed() {
            let sig_start = payload_end;
            let sig_end = sig_start + 32;
            if data.len() < sig_end {
                return Err(NegotiationError::TooShort {
                    expected: sig_end,
                    actual: data.len(),
                });
            }
            Some(data[sig_start..sig_end].try_into().expect("length checked"))
        } else {
            None
        };

        Ok(Self {
            header,
            payload,
            signature,
        })
    }
}

/// Request for a checkpoint
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckpointRequest {
    /// Request latest full checkpoint
    Latest,
    /// Request checkpoint at specific state
    AtState(u64),
    /// Request incremental from specified base
    IncrementalFrom(u64),
}

impl CheckpointRequest {
    /// Encode to bytes
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Self::Latest => vec![0x00],
            Self::AtState(state) => {
                let mut buf = vec![0x01];
                buf.extend_from_slice(&state.to_le_bytes());
                buf
            }
            Self::IncrementalFrom(base) => {
                let mut buf = vec![0x02];
                buf.extend_from_slice(&base.to_le_bytes());
                buf
            }
        }
    }

    /// Decode from bytes
    pub fn decode(data: &[u8]) -> Result<Self, NegotiationError> {
        if data.is_empty() {
            return Err(NegotiationError::TooShort {
                expected: 1,
                actual: 0,
            });
        }

        match data[0] {
            0x00 => Ok(Self::Latest),
            0x01 => {
                if data.len() < 9 {
                    return Err(NegotiationError::TooShort {
                        expected: 9,
                        actual: data.len(),
                    });
                }
                let state = u64::from_le_bytes(data[1..9].try_into().expect("length checked"));
                Ok(Self::AtState(state))
            }
            0x02 => {
                if data.len() < 9 {
                    return Err(NegotiationError::TooShort {
                        expected: 9,
                        actual: data.len(),
                    });
                }
                let base = u64::from_le_bytes(data[1..9].try_into().expect("length checked"));
                Ok(Self::IncrementalFrom(base))
            }
            _ => Err(NegotiationError::InvalidData),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_default() {
        let config = CheckpointConfig::default();
        assert!(config.supports_client_request());
        assert!(!config.supports_periodic());
        assert!(config.supports_compressed());
    }

    #[test]
    fn test_config_extension_roundtrip() {
        let config = CheckpointConfig {
            flags: checkpoint_config_flags::CLIENT_REQUEST | checkpoint_config_flags::INCREMENTAL,
            max_size: 8 * 1024 * 1024,
            interval_secs: 120,
        };

        let ext = config.to_extension();
        let decoded = CheckpointConfig::from_extension(&ext).unwrap();
        assert_eq!(decoded, config);
    }

    #[test]
    fn test_config_negotiate() {
        let client = CheckpointConfig {
            flags: checkpoint_config_flags::CLIENT_REQUEST | checkpoint_config_flags::COMPRESSED,
            max_size: 32 * 1024 * 1024,
            interval_secs: 60,
        };
        let server = CheckpointConfig {
            flags: checkpoint_config_flags::CLIENT_REQUEST | checkpoint_config_flags::PERIODIC,
            max_size: 16 * 1024 * 1024,
            interval_secs: 300,
        };

        let result = CheckpointConfig::negotiate(&client, &server);
        assert!(result.supports_client_request());
        assert!(!result.supports_compressed()); // Only client
        assert!(!result.supports_periodic()); // Only server
        assert_eq!(result.max_size, 16 * 1024 * 1024);
        assert_eq!(result.interval_secs, 300); // Use longer
    }

    #[test]
    fn test_header_roundtrip() {
        let header = CheckpointHeader::full(12345, 100, 4096);
        let encoded = header.encode();
        let decoded = CheckpointHeader::decode(&encoded).unwrap();
        assert_eq!(decoded, header);
    }

    #[test]
    fn test_incremental_header() {
        let header = CheckpointHeader::incremental(200, 150, 100, 1024);
        assert!(header.is_incremental());
        assert_eq!(header.base_id, 100);

        let encoded = header.encode();
        let decoded = CheckpointHeader::decode(&encoded).unwrap();
        assert!(decoded.is_incremental());
        assert_eq!(decoded.base_id, 100);
    }

    #[test]
    fn test_checkpoint_roundtrip() {
        let data = vec![1, 2, 3, 4, 5, 6, 7, 8];
        let checkpoint = Checkpoint::new(42, 10, data.clone());

        let encoded = checkpoint.encode();
        let decoded = Checkpoint::decode(&encoded).unwrap();

        assert_eq!(decoded.header.checkpoint_id, 42);
        assert_eq!(decoded.header.state_num, 10);
        assert_eq!(decoded.payload, data);
        assert!(decoded.signature.is_none());
    }

    #[test]
    fn test_checkpoint_with_signature() {
        let mut checkpoint = Checkpoint::new(1, 1, vec![0xAB; 100]);
        checkpoint.header.set_signed();
        checkpoint.signature = Some([0xCD; 32]);

        let encoded = checkpoint.encode();
        let decoded = Checkpoint::decode(&encoded).unwrap();

        assert!(decoded.header.is_signed());
        assert_eq!(decoded.signature, Some([0xCD; 32]));
    }

    #[test]
    fn test_request_roundtrip() {
        for request in [
            CheckpointRequest::Latest,
            CheckpointRequest::AtState(999),
            CheckpointRequest::IncrementalFrom(500),
        ] {
            let encoded = request.encode();
            let decoded = CheckpointRequest::decode(&encoded).unwrap();
            assert_eq!(decoded, request);
        }
    }

    #[test]
    fn test_compressed_header() {
        let mut header = CheckpointHeader::full(1, 1, 10000);
        header.set_compressed(2500);

        assert!(header.is_compressed());
        assert_eq!(header.uncompressed_size, 10000);
        assert_eq!(header.payload_len, 2500);
    }
}
