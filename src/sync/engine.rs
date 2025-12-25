//! Sync engine
//!
//! Coordinates state synchronization between two endpoints.
//! Generic over the state type S which must implement SyncState.

use super::message::{MessageError, SyncMessage};
use super::tracker::SyncTracker;
use thiserror::Error;

/// Errors from the sync engine.
#[derive(Debug, Error)]
pub enum SyncError {
    /// Error encoding or decoding sync messages.
    #[error("message error: {0}")]
    Message(#[from] MessageError),

    /// Failed to decode the diff payload.
    #[error("diff decode error: {0}")]
    DiffDecode(String),

    /// Failed to apply the diff to local state.
    #[error("diff apply error: {0}")]
    DiffApply(String),

    /// Diff was based on a different version than expected.
    #[error("version mismatch: expected base {expected}, got {actual}")]
    VersionMismatch {
        /// The base version we expected.
        expected: u64,
        /// The base version received.
        actual: u64,
    },

    /// Operation requires initialized state but none exists.
    #[error("state not initialized")]
    NotInitialized,
}

/// Result of processing an incoming sync message
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProcessResult {
    /// State was updated with the diff
    Updated,
    /// Message was ack-only, no state change
    AckOnly,
    /// Duplicate message (already have this version)
    Duplicate,
}

/// Sync engine for bidirectional state synchronization
///
/// The engine is generic over:
/// - `S`: The state type being synchronized
/// - `D`: The diff type for that state
///
/// The engine manages:
/// - Version tracking via SyncTracker
/// - State snapshots for diff computation
/// - Diff generation and application
pub struct SyncEngine<S, D> {
    /// Version tracking
    tracker: SyncTracker,

    /// Current local state
    state: Option<S>,

    /// State snapshot at last_acked version (for diff computation)
    /// This is the state we know the peer has
    acked_snapshot: Option<S>,

    /// Callback for encoding diffs
    encode_diff: fn(&D) -> Vec<u8>,

    /// Callback for decoding diffs
    decode_diff: fn(&[u8]) -> Result<D, String>,

    /// Callback for computing diff between states
    compute_diff: fn(&S, &S) -> D,

    /// Callback for applying diff to state
    apply_diff: fn(&mut S, &D) -> Result<(), String>,

    /// Callback for checking if diff is empty
    is_diff_empty: fn(&D) -> bool,
}

impl<S: Clone, D> SyncEngine<S, D> {
    /// Create a new sync engine with the required callbacks
    pub fn new(
        encode_diff: fn(&D) -> Vec<u8>,
        decode_diff: fn(&[u8]) -> Result<D, String>,
        compute_diff: fn(&S, &S) -> D,
        apply_diff: fn(&mut S, &D) -> Result<(), String>,
        is_diff_empty: fn(&D) -> bool,
    ) -> Self {
        Self {
            tracker: SyncTracker::new(),
            state: None,
            acked_snapshot: None,
            encode_diff,
            decode_diff,
            compute_diff,
            apply_diff,
            is_diff_empty,
        }
    }

    /// Initialize the engine with initial state
    pub fn init(&mut self, initial_state: S) {
        self.state = Some(initial_state.clone());
        self.acked_snapshot = Some(initial_state);
        self.tracker.reset();
    }

    /// Check if the engine is initialized
    pub fn is_initialized(&self) -> bool {
        self.state.is_some()
    }

    /// Get a reference to the current state
    pub fn state(&self) -> Option<&S> {
        self.state.as_ref()
    }

    /// Get a mutable reference to the current state
    ///
    /// Note: After modifying, call `mark_changed()` to bump version
    pub fn state_mut(&mut self) -> Option<&mut S> {
        self.state.as_mut()
    }

    /// Mark that the local state has changed
    ///
    /// Call this after modifying the state to bump the version.
    pub fn mark_changed(&mut self) -> u64 {
        self.tracker.bump_version()
    }

    /// Update local state and bump version atomically
    pub fn update_state(&mut self, new_state: S) -> u64 {
        self.state = Some(new_state);
        self.tracker.bump_version()
    }

    /// Get the tracker for inspection
    pub fn tracker(&self) -> &SyncTracker {
        &self.tracker
    }

    /// Check if we have updates to send
    pub fn has_pending_updates(&self) -> bool {
        self.tracker.has_pending_updates()
    }

    /// Check if we need to send an ack
    pub fn needs_ack(&self) -> bool {
        self.tracker.needs_ack()
    }

    /// Generate a sync message to send to peer
    ///
    /// Returns None if there's nothing to send
    pub fn generate_message(&mut self) -> Result<Option<SyncMessage>, SyncError> {
        let state = self.state.as_ref().ok_or(SyncError::NotInitialized)?;

        // If no pending updates and no ack needed, nothing to send
        if !self.tracker.has_pending_updates() && !self.tracker.needs_ack() {
            return Ok(None);
        }

        // If only need ack, send ack-only
        if !self.tracker.has_pending_updates() {
            let msg = self.tracker.create_ack();
            return Ok(Some(msg));
        }

        // Compute diff from acked snapshot
        let base_state = self.acked_snapshot.as_ref().ok_or(SyncError::NotInitialized)?;
        let diff = (self.compute_diff)(base_state, state);

        // If diff is empty but we have pending updates, still send it
        // (version bump matters even without content change)
        let diff_bytes = if (self.is_diff_empty)(&diff) {
            Vec::new()
        } else {
            (self.encode_diff)(&diff)
        };

        let base_version = self.tracker.diff_base_version();
        let msg = self.tracker.create_message(diff_bytes, base_version);
        self.tracker.record_sent(self.tracker.current_version());

        Ok(Some(msg))
    }

    /// Generate an ack-only message
    pub fn generate_ack(&self) -> Result<SyncMessage, SyncError> {
        if !self.is_initialized() {
            return Err(SyncError::NotInitialized);
        }
        Ok(self.tracker.create_ack())
    }

    /// Process an incoming sync message
    ///
    /// Returns the result of processing
    pub fn process_message(&mut self, msg: &SyncMessage) -> Result<ProcessResult, SyncError> {
        let state = self.state.as_mut().ok_or(SyncError::NotInitialized)?;

        // Update tracker first (this handles ack fields)
        let is_new = self.tracker.process_incoming(msg);

        if msg.is_ack_only() {
            // Update acked snapshot if peer acked new version
            if msg.acked_state_num > 0 {
                self.update_acked_snapshot();
            }
            return Ok(ProcessResult::AckOnly);
        }

        if !is_new {
            return Ok(ProcessResult::Duplicate);
        }

        // Decode and apply diff
        if !msg.diff.is_empty() {
            let diff = (self.decode_diff)(&msg.diff)
                .map_err(SyncError::DiffDecode)?;
            (self.apply_diff)(state, &diff)
                .map_err(SyncError::DiffApply)?;
        }

        // Update acked snapshot if peer acked new version
        if msg.acked_state_num > 0 {
            self.update_acked_snapshot();
        }

        Ok(ProcessResult::Updated)
    }

    /// Update the acked snapshot to current state
    fn update_acked_snapshot(&mut self) {
        if let Some(state) = &self.state {
            // Only update if we have a valid ack
            if self.tracker.last_acked_version() > 0 {
                // For simplicity, snapshot current state
                // In practice, might want versioned history
                self.acked_snapshot = Some(state.clone());
            }
        }
    }

    /// Get current local version
    pub fn current_version(&self) -> u64 {
        self.tracker.current_version()
    }

    /// Get peer's version
    pub fn peer_version(&self) -> u64 {
        self.tracker.peer_version()
    }

    /// Check if synchronized with peer
    pub fn is_synchronized(&self) -> bool {
        self.tracker.is_synchronized()
    }

    /// Reset the engine
    pub fn reset(&mut self) {
        self.tracker.reset();
        self.state = None;
        self.acked_snapshot = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Simple test state type
    #[derive(Debug, Clone, PartialEq)]
    struct TestState {
        value: i32,
    }

    // Simple diff type
    #[derive(Debug, Clone, PartialEq)]
    struct TestDiff {
        delta: i32,
    }

    fn encode_diff(diff: &TestDiff) -> Vec<u8> {
        diff.delta.to_le_bytes().to_vec()
    }

    fn decode_diff(data: &[u8]) -> Result<TestDiff, String> {
        if data.len() != 4 {
            return Err("invalid diff length".to_string());
        }
        let delta = i32::from_le_bytes(data.try_into().unwrap());
        Ok(TestDiff { delta })
    }

    fn compute_diff(old: &TestState, new: &TestState) -> TestDiff {
        TestDiff {
            delta: new.value - old.value,
        }
    }

    fn apply_diff(state: &mut TestState, diff: &TestDiff) -> Result<(), String> {
        state.value += diff.delta;
        Ok(())
    }

    fn is_diff_empty(diff: &TestDiff) -> bool {
        diff.delta == 0
    }

    fn create_engine() -> SyncEngine<TestState, TestDiff> {
        SyncEngine::new(encode_diff, decode_diff, compute_diff, apply_diff, is_diff_empty)
    }

    #[test]
    fn test_init() {
        let mut engine = create_engine();
        assert!(!engine.is_initialized());

        engine.init(TestState { value: 42 });
        assert!(engine.is_initialized());
        assert_eq!(engine.state().unwrap().value, 42);
    }

    #[test]
    fn test_update_state() {
        let mut engine = create_engine();
        engine.init(TestState { value: 0 });

        let version = engine.update_state(TestState { value: 100 });
        assert_eq!(version, 1);
        assert_eq!(engine.state().unwrap().value, 100);
        assert!(engine.has_pending_updates());
    }

    #[test]
    fn test_generate_message() {
        let mut engine = create_engine();
        engine.init(TestState { value: 0 });

        // No pending updates initially
        let msg = engine.generate_message().unwrap();
        assert!(msg.is_none());

        // Update state
        engine.update_state(TestState { value: 10 });

        // Now should generate message
        let msg = engine.generate_message().unwrap().unwrap();
        assert_eq!(msg.sender_state_num, 1);
        assert!(!msg.is_ack_only());

        // Diff should encode the delta
        let diff = decode_diff(&msg.diff).unwrap();
        assert_eq!(diff.delta, 10);
    }

    #[test]
    fn test_process_message() {
        let mut engine = create_engine();
        engine.init(TestState { value: 0 });

        // Create incoming message with diff
        let diff = TestDiff { delta: 50 };
        let msg = SyncMessage::new(1, 0, 0, encode_diff(&diff));

        let result = engine.process_message(&msg).unwrap();
        assert_eq!(result, ProcessResult::Updated);
        assert_eq!(engine.state().unwrap().value, 50);
        assert_eq!(engine.peer_version(), 1);
    }

    #[test]
    fn test_process_ack_only() {
        let mut engine = create_engine();
        engine.init(TestState { value: 0 });
        engine.update_state(TestState { value: 10 });

        let msg = SyncMessage::ack_only(1, 1);
        let result = engine.process_message(&msg).unwrap();
        assert_eq!(result, ProcessResult::AckOnly);
    }

    #[test]
    fn test_duplicate_message() {
        let mut engine = create_engine();
        engine.init(TestState { value: 0 });

        let diff = TestDiff { delta: 10 };
        let msg = SyncMessage::new(1, 0, 0, encode_diff(&diff));

        // First message
        engine.process_message(&msg).unwrap();

        // Same message again (same sender_state_num)
        let result = engine.process_message(&msg).unwrap();
        assert_eq!(result, ProcessResult::Duplicate);
    }

    #[test]
    fn test_bidirectional_sync() {
        let mut engine_a = create_engine();
        let mut engine_b = create_engine();

        engine_a.init(TestState { value: 0 });
        engine_b.init(TestState { value: 0 });

        // A updates state
        engine_a.update_state(TestState { value: 100 });
        let msg_from_a = engine_a.generate_message().unwrap().unwrap();

        // B receives and processes
        engine_b.process_message(&msg_from_a).unwrap();
        assert_eq!(engine_b.state().unwrap().value, 100);
        assert_eq!(engine_b.peer_version(), 1);

        // B sends ack back
        let ack_from_b = engine_b.generate_ack().unwrap();
        engine_a.process_message(&ack_from_b).unwrap();

        // A should see B acked version 1
        assert_eq!(engine_a.tracker().last_acked_version(), 1);
    }

    #[test]
    fn test_not_initialized_error() {
        let mut engine = create_engine();

        let result = engine.generate_message();
        assert!(matches!(result, Err(SyncError::NotInitialized)));

        let msg = SyncMessage::ack_only(1, 0);
        let result = engine.process_message(&msg);
        assert!(matches!(result, Err(SyncError::NotInitialized)));
    }

    #[test]
    fn test_empty_diff() {
        let mut engine = create_engine();
        engine.init(TestState { value: 42 });

        // Mark changed but with same value (empty diff)
        engine.mark_changed();

        let msg = engine.generate_message().unwrap().unwrap();
        // Should still send a message (version bump matters)
        // But diff should be empty
        assert!(msg.diff.is_empty() || msg.is_ack_only());
    }

    #[test]
    fn test_reset() {
        let mut engine = create_engine();
        engine.init(TestState { value: 100 });
        engine.update_state(TestState { value: 200 });

        engine.reset();

        assert!(!engine.is_initialized());
        assert!(engine.state().is_none());
        assert_eq!(engine.current_version(), 0);
    }
}
