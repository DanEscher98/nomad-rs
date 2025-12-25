//! Receiver-side sync logic
//!
//! Handles incoming sync messages and manages duplicate detection.

use super::message::{MessageError, SyncMessage};

/// Result of receiving a sync message
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReceiveResult {
    /// New state update received
    NewState {
        /// The sender's version
        sender_version: u64,
        /// Version acknowledged by sender
        acked_version: u64,
        /// Base version for the diff
        base_version: u64,
    },
    /// Ack-only message (no state change)
    AckOnly {
        /// The sender's version
        sender_version: u64,
        /// Version acknowledged by sender
        acked_version: u64,
    },
    /// Duplicate message (already seen this version)
    Duplicate {
        /// The version that was duplicated
        version: u64,
    },
    /// Old message (version lower than already received)
    Stale {
        /// The stale version received
        received: u64,
        /// Our current peer version
        current: u64,
    },
}

/// Receiver for incoming sync messages
///
/// Tracks received versions and detects duplicates/stale messages.
#[derive(Debug, Clone)]
pub struct SyncReceiver {
    /// Highest version received from peer
    highest_received: u64,

    /// Version we've acknowledged to peer
    last_acked_to_peer: u64,
}

impl SyncReceiver {
    /// Create a new receiver
    pub fn new() -> Self {
        Self {
            highest_received: 0,
            last_acked_to_peer: 0,
        }
    }

    /// Get highest version received from peer
    pub fn highest_received(&self) -> u64 {
        self.highest_received
    }

    /// Get last version we acknowledged to peer
    pub fn last_acked_to_peer(&self) -> u64 {
        self.last_acked_to_peer
    }

    /// Check if we need to send an ack
    pub fn needs_ack(&self) -> bool {
        self.highest_received > self.last_acked_to_peer
    }

    /// Mark that we've sent an ack for the given version
    pub fn mark_acked(&mut self, version: u64) {
        if version > self.last_acked_to_peer {
            self.last_acked_to_peer = version;
        }
    }

    /// Process a raw message from wire format
    pub fn receive_raw(&mut self, data: &[u8]) -> Result<(ReceiveResult, SyncMessage), MessageError> {
        let msg = SyncMessage::decode(data)?;
        let result = self.receive(&msg);
        Ok((result, msg))
    }

    /// Process an already-decoded message
    pub fn receive(&mut self, msg: &SyncMessage) -> ReceiveResult {
        let sender_version = msg.sender_state_num;

        // Check for stale/duplicate
        if sender_version < self.highest_received {
            return ReceiveResult::Stale {
                received: sender_version,
                current: self.highest_received,
            };
        }

        if sender_version == self.highest_received && sender_version > 0 {
            return ReceiveResult::Duplicate {
                version: sender_version,
            };
        }

        // New message
        self.highest_received = sender_version;

        if msg.is_ack_only() {
            ReceiveResult::AckOnly {
                sender_version,
                acked_version: msg.acked_state_num,
            }
        } else {
            ReceiveResult::NewState {
                sender_version,
                acked_version: msg.acked_state_num,
                base_version: msg.base_state_num,
            }
        }
    }

    /// Reset receiver state
    pub fn reset(&mut self) {
        self.highest_received = 0;
        self.last_acked_to_peer = 0;
    }
}

impl Default for SyncReceiver {
    fn default() -> Self {
        Self::new()
    }
}

/// Receiver with history for out-of-order message handling
///
/// Maintains a sliding window of received versions for detecting
/// duplicates even when messages arrive out of order.
#[derive(Debug, Clone)]
pub struct OrderedReceiver {
    /// Base receiver
    inner: SyncReceiver,

    /// Bitmap of received versions (sliding window)
    /// The highest bit (bit 63) always represents highest_received.
    /// Bit i represents version: highest_received - (63 - i)
    /// So bit 63 = highest_received, bit 62 = highest_received - 1, etc.
    received_bitmap: u64,
}

/// Size of the duplicate detection window
const WINDOW_SIZE: u64 = 64;

impl OrderedReceiver {
    /// Create a new ordered receiver
    pub fn new() -> Self {
        Self {
            inner: SyncReceiver::new(),
            received_bitmap: 0,
        }
    }

    /// Get highest version received from peer
    pub fn highest_received(&self) -> u64 {
        self.inner.highest_received
    }

    /// Check if we need to send an ack
    pub fn needs_ack(&self) -> bool {
        self.inner.needs_ack()
    }

    /// Mark that we've sent an ack
    pub fn mark_acked(&mut self, version: u64) {
        self.inner.mark_acked(version);
    }

    /// Convert version to bit index in the bitmap
    /// Returns None if version is outside the window
    fn version_to_bit_index(&self, version: u64) -> Option<usize> {
        if version == 0 || version > self.inner.highest_received {
            return None;
        }

        let offset = self.inner.highest_received - version;
        if offset >= WINDOW_SIZE {
            return None; // Too old
        }

        // bit 63 = highest_received (offset 0)
        // bit 62 = highest_received - 1 (offset 1)
        // ...
        Some((63 - offset) as usize)
    }

    /// Check if a version has been received
    pub fn has_received(&self, version: u64) -> bool {
        if version > self.inner.highest_received {
            return false;
        }

        if version == 0 {
            return true; // Version 0 is initial state
        }

        // If too old for window, assume received
        let offset = self.inner.highest_received - version;
        if offset >= WINDOW_SIZE {
            return true;
        }

        match self.version_to_bit_index(version) {
            Some(bit_index) => (self.received_bitmap & (1u64 << bit_index)) != 0,
            None => true, // Out of window, assume received
        }
    }

    /// Process an already-decoded message
    pub fn receive(&mut self, msg: &SyncMessage) -> ReceiveResult {
        let sender_version = msg.sender_state_num;

        // Check if we've already received this version
        if self.has_received(sender_version) && sender_version > 0 {
            return ReceiveResult::Duplicate {
                version: sender_version,
            };
        }

        // Update bitmap
        if sender_version > self.inner.highest_received {
            // Shift bitmap for new highest
            let shift = sender_version - self.inner.highest_received;
            if shift >= WINDOW_SIZE {
                // Complete reset, only new version is set
                self.received_bitmap = 1u64 << 63;
            } else {
                // Shift existing bits down and set new highest
                self.received_bitmap >>= shift;
                self.received_bitmap |= 1u64 << 63;
            }
        } else if sender_version > 0 {
            // Mark in existing bitmap (out of order arrival)
            if let Some(bit_index) = self.version_to_bit_index(sender_version) {
                self.received_bitmap |= 1u64 << bit_index;
            }
        }

        // Update inner receiver (updates highest_received)
        self.inner.receive(msg)
    }

    /// Reset receiver state
    pub fn reset(&mut self) {
        self.inner.reset();
        self.received_bitmap = 0;
    }
}

impl Default for OrderedReceiver {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_state_msg(version: u64) -> SyncMessage {
        SyncMessage::new(version, 0, 0, vec![1, 2, 3])
    }

    fn create_ack_msg(sender_version: u64, acked_version: u64) -> SyncMessage {
        SyncMessage::ack_only(sender_version, acked_version)
    }

    mod sync_receiver {
        use super::*;

        #[test]
        fn test_new_receiver() {
            let receiver = SyncReceiver::new();
            assert_eq!(receiver.highest_received(), 0);
            assert!(!receiver.needs_ack());
        }

        #[test]
        fn test_receive_new_state() {
            let mut receiver = SyncReceiver::new();

            let result = receiver.receive(&create_state_msg(1));

            assert!(matches!(result, ReceiveResult::NewState { sender_version: 1, .. }));
            assert_eq!(receiver.highest_received(), 1);
            assert!(receiver.needs_ack());
        }

        #[test]
        fn test_receive_ack_only() {
            let mut receiver = SyncReceiver::new();

            let result = receiver.receive(&create_ack_msg(1, 5));

            assert!(matches!(
                result,
                ReceiveResult::AckOnly { sender_version: 1, acked_version: 5 }
            ));
        }

        #[test]
        fn test_duplicate_detection() {
            let mut receiver = SyncReceiver::new();

            receiver.receive(&create_state_msg(5));
            let result = receiver.receive(&create_state_msg(5));

            assert!(matches!(result, ReceiveResult::Duplicate { version: 5 }));
        }

        #[test]
        fn test_stale_detection() {
            let mut receiver = SyncReceiver::new();

            receiver.receive(&create_state_msg(10));
            let result = receiver.receive(&create_state_msg(5));

            assert!(matches!(
                result,
                ReceiveResult::Stale { received: 5, current: 10 }
            ));
        }

        #[test]
        fn test_needs_ack() {
            let mut receiver = SyncReceiver::new();

            assert!(!receiver.needs_ack());

            receiver.receive(&create_state_msg(1));
            assert!(receiver.needs_ack());

            receiver.mark_acked(1);
            assert!(!receiver.needs_ack());

            receiver.receive(&create_state_msg(2));
            assert!(receiver.needs_ack());
        }

        #[test]
        fn test_reset() {
            let mut receiver = SyncReceiver::new();
            receiver.receive(&create_state_msg(5));
            receiver.mark_acked(5);

            receiver.reset();

            assert_eq!(receiver.highest_received(), 0);
            assert_eq!(receiver.last_acked_to_peer(), 0);
        }
    }

    mod ordered_receiver {
        use super::*;

        #[test]
        fn test_out_of_order_duplicate() {
            let mut receiver = OrderedReceiver::new();

            // Receive 1, 2, 3
            receiver.receive(&create_state_msg(1));
            receiver.receive(&create_state_msg(2));
            receiver.receive(&create_state_msg(3));

            // Receive 2 again (out of order duplicate)
            let result = receiver.receive(&create_state_msg(2));
            assert!(matches!(result, ReceiveResult::Duplicate { version: 2 }));
        }

        #[test]
        fn test_has_received() {
            let mut receiver = OrderedReceiver::new();

            receiver.receive(&create_state_msg(5));
            receiver.receive(&create_state_msg(10));
            receiver.receive(&create_state_msg(7)); // Out of order

            assert!(receiver.has_received(5));
            assert!(receiver.has_received(7));
            assert!(receiver.has_received(10));
            assert!(!receiver.has_received(6));
            assert!(!receiver.has_received(8));
        }

        #[test]
        fn test_window_sliding() {
            let mut receiver = OrderedReceiver::new();

            // Receive version 1
            receiver.receive(&create_state_msg(1));
            assert!(receiver.has_received(1));

            // Receive version 100 (slides window past 1)
            receiver.receive(&create_state_msg(100));

            // Version 1 should still be considered received (too old, assume true)
            assert!(receiver.has_received(1));
        }

        #[test]
        fn test_reset() {
            let mut receiver = OrderedReceiver::new();
            receiver.receive(&create_state_msg(5));

            receiver.reset();

            assert_eq!(receiver.highest_received(), 0);
            assert!(!receiver.has_received(5));
        }
    }
}
