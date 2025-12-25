// NOMAD Protocol - Core Traits Contract
// This is the single source of truth for trait signatures.
// Tentacles MUST implement these exactly as specified.

/// Core trait for any state that can be synchronized.
/// Implements 3-SYNC.md state type interface.
pub trait SyncState: Clone + Send + Sync + 'static {
    /// Diff representation (must be idempotent when applied)
    type Diff: Clone + Send + Sync;

    /// Unique type identifier (e.g., "nomad.echo.v1")
    const STATE_TYPE_ID: &'static str;

    /// Create diff from old_state to self.
    /// MUST be idempotent: applying twice has no additional effect.
    fn diff_from(&self, old: &Self) -> Self::Diff;

    /// Apply diff to produce new state.
    /// MUST handle repeated application (idempotent).
    fn apply_diff(&mut self, diff: &Self::Diff) -> Result<(), ApplyError>;

    /// Serialize diff for wire transmission.
    fn encode_diff(diff: &Self::Diff) -> Vec<u8>;

    /// Deserialize diff from wire format.
    fn decode_diff(data: &[u8]) -> Result<Self::Diff, DecodeError>;

    /// Check if diff is empty (optimization for ack-only).
    fn is_diff_empty(diff: &Self::Diff) -> bool {
        false
    }
}

/// Optional trait for states that support client-side prediction.
/// See 4-EXTENSIONS.md §Prediction.
pub trait Predictable: SyncState {
    /// User input type (e.g., keystrokes)
    type Input;

    /// Apply speculative input locally
    fn predict(&mut self, input: &Self::Input);

    /// Reconcile with authoritative server state
    fn reconcile(&mut self, authoritative: &Self);
}

// Error types defined in errors.rs
pub use super::errors::{ApplyError, DecodeError};
