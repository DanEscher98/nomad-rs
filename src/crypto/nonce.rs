//! Nonce construction for XChaCha20-Poly1305
//!
//! Per 1-SECURITY.md, nonces are 24 bytes:
//! - Epoch (4 bytes)
//! - Direction (1 byte): 0x00 = Initiator→Responder, 0x01 = Responder→Initiator
//! - Zeros (11 bytes)
//! - Counter (8 bytes)

use crate::core::{AEAD_NONCE_SIZE, NONCE_DIR_INITIATOR, NONCE_DIR_RESPONDER};

/// Direction of communication for nonce construction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    /// Initiator → Responder (0x00)
    InitiatorToResponder,
    /// Responder → Initiator (0x01)
    ResponderToInitiator,
}

impl Direction {
    /// Get the byte representation.
    pub fn as_byte(self) -> u8 {
        match self {
            Direction::InitiatorToResponder => NONCE_DIR_INITIATOR,
            Direction::ResponderToInitiator => NONCE_DIR_RESPONDER,
        }
    }

    /// Get the opposite direction.
    pub fn opposite(self) -> Self {
        match self {
            Direction::InitiatorToResponder => Direction::ResponderToInitiator,
            Direction::ResponderToInitiator => Direction::InitiatorToResponder,
        }
    }
}

/// Construct a 24-byte XChaCha20-Poly1305 nonce.
///
/// Layout:
/// ```text
/// [ epoch (4) | direction (1) | zeros (11) | counter (8) ]
/// ```
///
/// # Arguments
/// * `epoch` - Current key epoch (increments on rekey)
/// * `direction` - Communication direction
/// * `counter` - Per-direction frame counter
pub fn construct_nonce(epoch: u32, direction: Direction, counter: u64) -> [u8; AEAD_NONCE_SIZE] {
    let mut nonce = [0u8; AEAD_NONCE_SIZE];

    // Epoch (bytes 0-3, little-endian)
    nonce[0..4].copy_from_slice(&epoch.to_le_bytes());

    // Direction (byte 4)
    nonce[4] = direction.as_byte();

    // Zeros (bytes 5-15) - already zeroed

    // Counter (bytes 16-23, little-endian)
    nonce[16..24].copy_from_slice(&counter.to_le_bytes());

    nonce
}

/// Parse a nonce back into its components.
///
/// Useful for debugging and testing.
pub fn parse_nonce(nonce: &[u8; AEAD_NONCE_SIZE]) -> (u32, Direction, u64) {
    let epoch = u32::from_le_bytes([nonce[0], nonce[1], nonce[2], nonce[3]]);

    let direction = if nonce[4] == NONCE_DIR_INITIATOR {
        Direction::InitiatorToResponder
    } else {
        Direction::ResponderToInitiator
    };

    let counter = u64::from_le_bytes([
        nonce[16], nonce[17], nonce[18], nonce[19], nonce[20], nonce[21], nonce[22], nonce[23],
    ]);

    (epoch, direction, counter)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nonce_construction() {
        let nonce = construct_nonce(1, Direction::InitiatorToResponder, 42);

        assert_eq!(nonce.len(), AEAD_NONCE_SIZE);

        // Verify epoch
        assert_eq!(&nonce[0..4], &1u32.to_le_bytes());

        // Verify direction
        assert_eq!(nonce[4], 0x00);

        // Verify zeros
        assert_eq!(&nonce[5..16], &[0u8; 11]);

        // Verify counter
        assert_eq!(&nonce[16..24], &42u64.to_le_bytes());
    }

    #[test]
    fn test_nonce_roundtrip() {
        let epoch = 0x12345678;
        let direction = Direction::ResponderToInitiator;
        let counter = 0xDEADBEEFCAFEBABE;

        let nonce = construct_nonce(epoch, direction, counter);
        let (parsed_epoch, parsed_dir, parsed_counter) = parse_nonce(&nonce);

        assert_eq!(parsed_epoch, epoch);
        assert_eq!(parsed_dir, direction);
        assert_eq!(parsed_counter, counter);
    }

    #[test]
    fn test_direction_opposite() {
        assert_eq!(
            Direction::InitiatorToResponder.opposite(),
            Direction::ResponderToInitiator
        );
        assert_eq!(
            Direction::ResponderToInitiator.opposite(),
            Direction::InitiatorToResponder
        );
    }

    #[test]
    fn test_direction_bytes() {
        assert_eq!(Direction::InitiatorToResponder.as_byte(), 0x00);
        assert_eq!(Direction::ResponderToInitiator.as_byte(), 0x01);
    }
}
