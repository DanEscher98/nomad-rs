// NOMAD Protocol - Frame Types Contract
// From 2-TRANSPORT.md
// Tentacles MUST use these exact structures.

/// Frame type enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FrameType {
    HandshakeInit = 0x01,
    HandshakeResp = 0x02,
    Data = 0x03,
    Rekey = 0x04,
    Close = 0x05,
}

impl TryFrom<u8> for FrameType {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(Self::HandshakeInit),
            0x02 => Ok(Self::HandshakeResp),
            0x03 => Ok(Self::Data),
            0x04 => Ok(Self::Rekey),
            0x05 => Ok(Self::Close),
            _ => Err(()),
        }
    }
}

/// Data frame header (16 bytes, used as AAD)
///
/// Wire format:
/// ```text
/// +0   Type (1 byte)
/// +1   Flags (1 byte)
/// +2   Session ID (6 bytes)
/// +8   Nonce Counter (8 bytes LE64)
/// ```
#[derive(Debug, Clone)]
pub struct DataFrameHeader {
    pub frame_type: FrameType,
    pub flags: u8,
    pub session_id: [u8; 6],
    pub nonce_counter: u64,
}

/// Decrypted payload structure
///
/// Wire format after decryption:
/// ```text
/// +0   Timestamp (4 bytes LE32, ms since session start)
/// +4   Timestamp Echo (4 bytes LE32)
/// +8   Payload Length (2 bytes LE16)
/// +10  Sync Message (variable)
/// ```
#[derive(Debug, Clone)]
pub struct PayloadHeader {
    pub timestamp: u32,
    pub timestamp_echo: u32,
    pub payload_length: u16,
}

/// Handshake Init frame (Type 0x01)
///
/// Wire format:
/// ```text
/// +0   Type 0x01 (1 byte)
/// +1   Reserved 0x00 (1 byte)
/// +2   Protocol Version (2 bytes LE16)
/// +4   Initiator Ephemeral Public Key (32 bytes)
/// +36  Encrypted Initiator Static (48 bytes = 32 + 16 tag)
/// +84  Encrypted Payload (variable, min 16 tag)
/// ```
#[derive(Debug, Clone)]
pub struct HandshakeInit {
    pub protocol_version: u16,
    pub ephemeral_public: [u8; 32],
    /// Encrypted: initiator's static public key + tag
    pub encrypted_static: [u8; 48],
    /// Encrypted: state type ID + extensions + tag
    pub encrypted_payload: Vec<u8>,
}

/// Handshake Response frame (Type 0x02)
///
/// Wire format:
/// ```text
/// +0   Type 0x02 (1 byte)
/// +1   Reserved 0x00 (1 byte)
/// +2   Session ID (6 bytes)
/// +8   Responder Ephemeral Public Key (32 bytes)
/// +40  Encrypted Payload (variable, min 16 tag)
/// ```
#[derive(Debug, Clone)]
pub struct HandshakeResp {
    pub session_id: [u8; 6],
    pub ephemeral_public: [u8; 32],
    /// Encrypted: ack + negotiated extensions + tag
    pub encrypted_payload: Vec<u8>,
}

/// Close frame (Type 0x05)
///
/// Wire format:
/// ```text
/// +0   Type 0x05 (1 byte)
/// +1   Flags 0x00 (1 byte)
/// +2   Session ID (6 bytes)
/// +8   Nonce Counter (8 bytes LE64)
/// +16  Encrypted Final Ack (8 bytes)
/// +24  AEAD Tag (16 bytes)
/// ```
#[derive(Debug, Clone)]
pub struct CloseFrame {
    pub session_id: [u8; 6],
    pub nonce_counter: u64,
    pub final_ack: u64,
}

/// Extension TLV format
///
/// Wire format:
/// ```text
/// +0   Extension Type (2 bytes LE16)
/// +2   Extension Length (2 bytes LE16)
/// +4   Extension Data (variable)
/// ```
#[derive(Debug, Clone)]
pub struct Extension {
    pub ext_type: u16,
    pub data: Vec<u8>,
}

/// AAD (Additional Authenticated Data) for AEAD
///
/// Exactly 16 bytes:
/// ```text
/// +0   Frame type (1 byte)
/// +1   Flags (1 byte)
/// +2   Session ID (6 bytes)
/// +8   Nonce counter (8 bytes LE64)
/// ```
pub fn build_aad(frame_type: u8, flags: u8, session_id: &[u8; 6], nonce_counter: u64) -> [u8; 16] {
    let mut aad = [0u8; 16];
    aad[0] = frame_type;
    aad[1] = flags;
    aad[2..8].copy_from_slice(session_id);
    aad[8..16].copy_from_slice(&nonce_counter.to_le_bytes());
    aad
}
