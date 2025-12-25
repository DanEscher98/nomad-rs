// NOMAD Protocol - Sync Message Types Contract
// From 3-SYNC.md
// Tentacles MUST use these exact structures.

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
#[derive(Debug, Clone)]
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

impl SyncMessage {
    /// Create a new sync message
    pub fn new(sender_state_num: u64, acked_state_num: u64, base_state_num: u64, diff: Vec<u8>) -> Self {
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

    /// Encode to wire format (28-byte header + diff)
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(28 + self.diff.len());
        buf.extend_from_slice(&self.sender_state_num.to_le_bytes());
        buf.extend_from_slice(&self.acked_state_num.to_le_bytes());
        buf.extend_from_slice(&self.base_state_num.to_le_bytes());
        buf.extend_from_slice(&(self.diff.len() as u32).to_le_bytes());
        buf.extend_from_slice(&self.diff);
        buf
    }

    /// Decode from wire format
    pub fn decode(data: &[u8]) -> Result<Self, DecodeError> {
        if data.len() < 28 {
            return Err(DecodeError::TooShort { expected: 28, actual: data.len() });
        }

        let sender_state_num = u64::from_le_bytes(data[0..8].try_into().unwrap());
        let acked_state_num = u64::from_le_bytes(data[8..16].try_into().unwrap());
        let base_state_num = u64::from_le_bytes(data[16..24].try_into().unwrap());
        let diff_len = u32::from_le_bytes(data[24..28].try_into().unwrap()) as usize;

        if data.len() < 28 + diff_len {
            return Err(DecodeError::TooShort { expected: 28 + diff_len, actual: data.len() });
        }

        let diff = data[28..28 + diff_len].to_vec();

        Ok(Self {
            sender_state_num,
            acked_state_num,
            base_state_num,
            diff,
        })
    }
}

/// Sync message decode errors
#[derive(Debug, Clone)]
pub enum DecodeError {
    TooShort { expected: usize, actual: usize },
    InvalidFormat(String),
}

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DecodeError::TooShort { expected, actual } => {
                write!(f, "message too short: expected {} bytes, got {}", expected, actual)
            }
            DecodeError::InvalidFormat(msg) => write!(f, "invalid format: {}", msg),
        }
    }
}

impl std::error::Error for DecodeError {}

/// Sync tracker state (each endpoint maintains this)
///
/// Generic over state type S that implements SyncState.
#[derive(Debug, Clone)]
pub struct SyncTrackerState {
    /// Version of current local state (monotonic)
    pub current_num: u64,
    /// Version of last sent state
    pub last_sent_num: u64,
    /// Highest version acked by peer
    pub last_acked: u64,
    /// Highest version received from peer
    pub peer_state_num: u64,
}

impl Default for SyncTrackerState {
    fn default() -> Self {
        Self {
            current_num: 0,
            last_sent_num: 0,
            last_acked: 0,
            peer_state_num: 0,
        }
    }
}
