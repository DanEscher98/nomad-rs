//! Protocol constants from NOMAD specifications.
//!
//! These values are fixed by the protocol and MUST NOT be changed.

use std::time::Duration;

// =============================================================================
// CRYPTOGRAPHIC CONSTANTS (1-SECURITY.md)
// =============================================================================

/// Poly1305 authentication tag size.
pub const AEAD_TAG_SIZE: usize = 16;

/// XChaCha20 nonce size.
pub const AEAD_NONCE_SIZE: usize = 24;

/// X25519 public key size.
pub const PUBLIC_KEY_SIZE: usize = 32;

/// X25519 private key size.
pub const PRIVATE_KEY_SIZE: usize = 32;

/// BLAKE2s hash output size.
pub const HASH_SIZE: usize = 32;

/// Session ID size (48-bit).
pub const SESSION_ID_SIZE: usize = 6;

/// Protocol version (v1.0).
pub const PROTOCOL_VERSION: u16 = 0x0001;

// =============================================================================
// FRAME TYPES (0-PROTOCOL.md)
// =============================================================================

/// Handshake initiation (Noise_IK first message).
pub const FRAME_TYPE_HANDSHAKE_INIT: u8 = 0x01;

/// Handshake response (Noise_IK second message).
pub const FRAME_TYPE_HANDSHAKE_RESP: u8 = 0x02;

/// Data frame (encrypted sync message).
pub const FRAME_TYPE_DATA: u8 = 0x03;

/// Rekey frame.
pub const FRAME_TYPE_REKEY: u8 = 0x04;

/// Close frame (graceful termination).
pub const FRAME_TYPE_CLOSE: u8 = 0x05;

// =============================================================================
// FRAME FLAGS (2-TRANSPORT.md)
// =============================================================================

/// Frame contains only acknowledgment, no state diff.
pub const FLAG_ACK_ONLY: u8 = 0x01;

/// Extension data follows payload.
pub const FLAG_HAS_EXTENSION: u8 = 0x02;

// =============================================================================
// FRAME SIZES (2-TRANSPORT.md)
// =============================================================================

/// Data frame header size (type + flags + session_id + nonce).
pub const DATA_FRAME_HEADER_SIZE: usize = 16;

/// Minimum data frame size (header + empty payload + tag).
pub const MIN_DATA_FRAME_SIZE: usize = 32;

/// Minimum handshake init size.
pub const MIN_HANDSHAKE_INIT_SIZE: usize = 100;

/// Minimum handshake response size.
pub const MIN_HANDSHAKE_RESP_SIZE: usize = 56;

/// Recommended max payload for mobile networks.
pub const RECOMMENDED_MAX_PAYLOAD: usize = 1200;

// =============================================================================
// TIMING CONSTANTS - TRANSPORT (2-TRANSPORT.md)
// =============================================================================

/// Initial retransmission timeout.
pub const INITIAL_RTO: Duration = Duration::from_millis(1000);

/// Minimum retransmission timeout.
pub const MIN_RTO: Duration = Duration::from_millis(100);

/// Maximum retransmission timeout.
pub const MAX_RTO: Duration = Duration::from_millis(60000);

/// Collection interval for batching rapid state changes.
pub const COLLECTION_INTERVAL: Duration = Duration::from_millis(8);

/// Maximum delay for ack-only frame.
pub const DELAYED_ACK_TIMEOUT: Duration = Duration::from_millis(100);

/// Maximum frame rate (Hz).
pub const MAX_FRAME_RATE: u32 = 50;

/// Minimum frame interval (ms) - will use max(SRTT/2, this).
pub const MIN_FRAME_INTERVAL_MS: u64 = 20;

/// Send keepalive if idle for this long.
pub const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(25);

/// Consider connection dead after this long without frames.
pub const DEAD_INTERVAL: Duration = Duration::from_secs(60);

/// Maximum retransmission attempts before giving up.
pub const MAX_RETRANSMITS: u32 = 10;

// =============================================================================
// TIMING CONSTANTS - SECURITY (1-SECURITY.md)
// =============================================================================

/// Initiate rekey after this time.
pub const REKEY_AFTER_TIME: Duration = Duration::from_secs(120);

/// Hard limit, reject old keys after this time.
pub const REJECT_AFTER_TIME: Duration = Duration::from_secs(180);

/// Soft limit on messages before rekey.
pub const REKEY_AFTER_MESSAGES: u64 = 1 << 60;

/// Hard limit on messages - MUST terminate session.
pub const REJECT_AFTER_MESSAGES: u64 = u64::MAX;

/// Maximum epoch value.
pub const MAX_EPOCH: u32 = u32::MAX;

/// Keep old keys for late packets during rekey.
pub const OLD_KEY_RETENTION: Duration = Duration::from_secs(5);

/// Handshake timeout (initial).
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_millis(1000);

/// Maximum handshake retries.
pub const HANDSHAKE_MAX_RETRIES: u32 = 5;

/// Handshake backoff multiplier.
pub const HANDSHAKE_BACKOFF: u32 = 2;

// =============================================================================
// ANTI-REPLAY (1-SECURITY.md)
// =============================================================================

/// Minimum replay window size in bits.
pub const REPLAY_WINDOW_SIZE: usize = 2048;

// =============================================================================
// SYNC MESSAGE (3-SYNC.md)
// =============================================================================

/// Sync message header size (3 x u64 + u32).
pub const SYNC_MESSAGE_HEADER_SIZE: usize = 28;

// =============================================================================
// EXTENSIONS (4-EXTENSIONS.md)
// =============================================================================

/// Extension type: Compression (zstd).
pub const EXT_COMPRESSION: u16 = 0x0001;

/// Extension type: Scrollback (terminal-specific).
pub const EXT_SCROLLBACK: u16 = 0x0002;

/// Extension type: Prediction (terminal-specific).
pub const EXT_PREDICTION: u16 = 0x0003;

/// Minimum size to attempt compression.
pub const MIN_COMPRESS_SIZE: usize = 64;

/// Default zstd compression level.
pub const DEFAULT_COMPRESSION_LEVEL: i32 = 3;

// =============================================================================
// NONCE DIRECTION (1-SECURITY.md)
// =============================================================================

/// Nonce direction: Initiator -> Responder.
pub const NONCE_DIR_INITIATOR: u8 = 0x00;

/// Nonce direction: Responder -> Initiator.
pub const NONCE_DIR_RESPONDER: u8 = 0x01;
