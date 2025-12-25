//! Sync state tracker
//!
//! Tracks local and remote state versions for synchronization.
//! Each endpoint maintains its own tracker instance.

use super::message::SyncMessage;

/// Sync tracker state (each endpoint maintains this)
///
/// Tracks version numbers for synchronization:
/// - `current_num`: Version of current local state
/// - `last_sent_num`: Version of last state we sent to peer
/// - `last_acked`: Highest version our peer acknowledged receiving
/// - `peer_state_num`: Highest version we've received from peer
#[derive(Debug, Clone, Default)]
pub struct SyncTracker {
    /// Version of current local state (monotonic)
    current_num: u64,
    /// Version of last sent state
    last_sent_num: u64,
    /// Highest version acked by peer
    last_acked: u64,
    /// Highest version received from peer
    peer_state_num: u64,
}

impl SyncTracker {
    /// Create a new sync tracker
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a tracker with initial state
    pub fn with_initial_version(version: u64) -> Self {
        Self {
            current_num: version,
            last_sent_num: 0,
            last_acked: 0,
            peer_state_num: 0,
        }
    }

    /// Get current local state version
    pub fn current_version(&self) -> u64 {
        self.current_num
    }

    /// Get last sent version
    pub fn last_sent_version(&self) -> u64 {
        self.last_sent_num
    }

    /// Get highest version acked by peer
    pub fn last_acked_version(&self) -> u64 {
        self.last_acked
    }

    /// Get highest version received from peer
    pub fn peer_version(&self) -> u64 {
        self.peer_state_num
    }

    /// Check if we have pending updates to send
    pub fn has_pending_updates(&self) -> bool {
        self.current_num > self.last_sent_num
    }

    /// Check if we need to send an ack
    pub fn needs_ack(&self) -> bool {
        self.peer_state_num > self.last_acked
    }

    /// Check if the state is in sync with peer
    pub fn is_synchronized(&self) -> bool {
        self.last_acked == self.current_num && !self.needs_ack()
    }

    /// Bump local state version (call when local state changes)
    pub fn bump_version(&mut self) -> u64 {
        self.current_num += 1;
        self.current_num
    }

    /// Record that we sent a message
    ///
    /// Returns the version number that was marked as sent.
    pub fn record_sent(&mut self, sent_version: u64) {
        if sent_version > self.last_sent_num {
            self.last_sent_num = sent_version;
        }
    }

    /// Process an incoming sync message
    ///
    /// Updates:
    /// - `peer_state_num` from the sender's current version
    /// - `last_acked` from the sender's ack field
    ///
    /// Returns `true` if the message contained new state (not just an ack).
    pub fn process_incoming(&mut self, msg: &SyncMessage) -> bool {
        // Update what peer has acked about our state
        if msg.acked_state_num > self.last_acked {
            self.last_acked = msg.acked_state_num;
        }

        // Update peer's state version if this is newer
        let is_new_state = msg.sender_state_num > self.peer_state_num;
        if is_new_state {
            self.peer_state_num = msg.sender_state_num;
        }

        is_new_state && !msg.is_ack_only()
    }

    /// Create a sync message with current state info
    ///
    /// The caller should fill in the diff payload.
    pub fn create_message(&self, diff: Vec<u8>, base_state_num: u64) -> SyncMessage {
        SyncMessage::new(
            self.current_num,
            self.peer_state_num,
            base_state_num,
            diff,
        )
    }

    /// Create an ack-only message
    pub fn create_ack(&self) -> SyncMessage {
        SyncMessage::ack_only(self.current_num, self.peer_state_num)
    }

    /// Reset the tracker to initial state
    pub fn reset(&mut self) {
        *self = Self::default();
    }

    /// Get the base state number that should be used for diff computation
    ///
    /// This is the last version we know the peer has acknowledged.
    pub fn diff_base_version(&self) -> u64 {
        self.last_acked
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_tracker() {
        let tracker = SyncTracker::new();
        assert_eq!(tracker.current_version(), 0);
        assert_eq!(tracker.last_sent_version(), 0);
        assert_eq!(tracker.last_acked_version(), 0);
        assert_eq!(tracker.peer_version(), 0);
    }

    #[test]
    fn test_bump_version() {
        let mut tracker = SyncTracker::new();

        assert_eq!(tracker.bump_version(), 1);
        assert_eq!(tracker.bump_version(), 2);
        assert_eq!(tracker.bump_version(), 3);
        assert_eq!(tracker.current_version(), 3);
    }

    #[test]
    fn test_has_pending_updates() {
        let mut tracker = SyncTracker::new();

        assert!(!tracker.has_pending_updates());

        tracker.bump_version();
        assert!(tracker.has_pending_updates());

        tracker.record_sent(1);
        assert!(!tracker.has_pending_updates());

        tracker.bump_version();
        assert!(tracker.has_pending_updates());
    }

    #[test]
    fn test_process_incoming() {
        let mut tracker = SyncTracker::new();
        tracker.bump_version(); // version = 1

        // Simulate receiving a message from peer with their version 5, acking our version 1
        let msg = SyncMessage::new(5, 1, 4, vec![1, 2, 3]);
        let has_new_state = tracker.process_incoming(&msg);

        assert!(has_new_state);
        assert_eq!(tracker.peer_version(), 5);
        assert_eq!(tracker.last_acked_version(), 1);
    }

    #[test]
    fn test_process_ack_only() {
        let mut tracker = SyncTracker::new();
        tracker.bump_version();
        tracker.bump_version(); // version = 2

        // Peer sends ack-only with their version 3, acking our version 2
        let msg = SyncMessage::ack_only(3, 2);
        let has_new_state = tracker.process_incoming(&msg);

        // Ack-only should not report as "new state" even though peer version updated
        assert!(!has_new_state);
        assert_eq!(tracker.peer_version(), 3);
        assert_eq!(tracker.last_acked_version(), 2);
    }

    #[test]
    fn test_needs_ack() {
        let mut tracker = SyncTracker::new();

        assert!(!tracker.needs_ack());

        // Receive a message
        let msg = SyncMessage::new(5, 0, 0, vec![1, 2, 3]);
        tracker.process_incoming(&msg);

        // We should need to ack
        assert!(tracker.needs_ack());
        assert_eq!(tracker.peer_version(), 5);
    }

    #[test]
    fn test_create_message() {
        let mut tracker = SyncTracker::new();
        tracker.bump_version(); // version = 1

        // Simulate having received peer version 3
        let incoming = SyncMessage::new(3, 0, 0, vec![]);
        tracker.process_incoming(&incoming);

        let msg = tracker.create_message(vec![10, 20, 30], 0);
        assert_eq!(msg.sender_state_num, 1);
        assert_eq!(msg.acked_state_num, 3); // Acking peer's version
        assert_eq!(msg.diff, vec![10, 20, 30]);
    }

    #[test]
    fn test_create_ack() {
        let mut tracker = SyncTracker::new();
        tracker.bump_version(); // version = 1

        // Simulate having received peer version 5
        let incoming = SyncMessage::new(5, 0, 0, vec![1]);
        tracker.process_incoming(&incoming);

        let ack = tracker.create_ack();
        assert!(ack.is_ack_only());
        assert_eq!(ack.sender_state_num, 1);
        assert_eq!(ack.acked_state_num, 5);
    }

    #[test]
    fn test_is_synchronized() {
        let mut tracker = SyncTracker::new();

        // Initially synchronized (both at 0)
        assert!(tracker.is_synchronized());

        // Bump version - not synced
        tracker.bump_version();
        assert!(!tracker.is_synchronized());

        // Simulate full sync cycle
        tracker.record_sent(1);
        let ack = SyncMessage::new(1, 1, 0, vec![]);
        tracker.process_incoming(&ack);

        // Now synchronized
        assert!(tracker.is_synchronized());
    }

    #[test]
    fn test_diff_base_version() {
        let mut tracker = SyncTracker::new();

        assert_eq!(tracker.diff_base_version(), 0);

        // Peer acks version 5
        let msg = SyncMessage::new(10, 5, 0, vec![]);
        tracker.process_incoming(&msg);

        // Now we should compute diffs from version 5
        // (But that's our version, peer acked 5, so we might need to adjust logic)
        // Actually, diff_base is about what peer knows about our state
        assert_eq!(tracker.diff_base_version(), 5);
    }

    #[test]
    fn test_with_initial_version() {
        let tracker = SyncTracker::with_initial_version(100);
        assert_eq!(tracker.current_version(), 100);
        assert_eq!(tracker.last_sent_version(), 0);
    }

    #[test]
    fn test_reset() {
        let mut tracker = SyncTracker::new();
        tracker.bump_version();
        tracker.bump_version();
        tracker.record_sent(2);

        let msg = SyncMessage::new(5, 2, 0, vec![1]);
        tracker.process_incoming(&msg);

        tracker.reset();

        assert_eq!(tracker.current_version(), 0);
        assert_eq!(tracker.last_sent_version(), 0);
        assert_eq!(tracker.last_acked_version(), 0);
        assert_eq!(tracker.peer_version(), 0);
    }
}
