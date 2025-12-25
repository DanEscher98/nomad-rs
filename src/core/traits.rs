//! Core traits for NOMAD protocol.
//!
//! These traits define the interface for state synchronization.

use super::error::{ApplyError, DecodeError};

/// Core trait for any state that can be synchronized.
///
/// Implements the state type interface from 3-SYNC.md.
///
/// # Requirements
///
/// - `diff_from` MUST produce idempotent diffs
/// - `apply_diff` MUST handle repeated application
/// - `encode_diff`/`decode_diff` MUST roundtrip correctly
///
/// # Example
///
/// ```ignore
/// #[derive(Clone)]
/// struct Counter { value: u64 }
///
/// #[derive(Clone)]
/// struct CounterDiff { delta: i64 }
///
/// impl SyncState for Counter {
///     type Diff = CounterDiff;
///     const STATE_TYPE_ID: &'static str = "example.counter.v1";
///
///     fn diff_from(&self, old: &Self) -> Self::Diff {
///         CounterDiff { delta: self.value as i64 - old.value as i64 }
///     }
///
///     fn apply_diff(&mut self, diff: &Self::Diff) -> Result<(), ApplyError> {
///         self.value = (self.value as i64 + diff.delta) as u64;
///         Ok(())
///     }
///
///     fn encode_diff(diff: &Self::Diff) -> Vec<u8> {
///         diff.delta.to_le_bytes().to_vec()
///     }
///
///     fn decode_diff(data: &[u8]) -> Result<Self::Diff, DecodeError> {
///         if data.len() < 8 {
///             return Err(DecodeError::UnexpectedEof);
///         }
///         let delta = i64::from_le_bytes(data[..8].try_into().unwrap());
///         Ok(CounterDiff { delta })
///     }
/// }
/// ```
pub trait SyncState: Clone + Send + Sync + 'static {
    /// Diff representation (must be idempotent when applied).
    type Diff: Clone + Send + Sync;

    /// Unique type identifier (e.g., "nomad.echo.v1").
    const STATE_TYPE_ID: &'static str;

    /// Create diff from old_state to self.
    ///
    /// MUST be idempotent: applying twice has no additional effect.
    fn diff_from(&self, old: &Self) -> Self::Diff;

    /// Apply diff to produce new state.
    ///
    /// MUST handle repeated application (idempotent).
    fn apply_diff(&mut self, diff: &Self::Diff) -> Result<(), ApplyError>;

    /// Serialize diff for wire transmission.
    fn encode_diff(diff: &Self::Diff) -> Vec<u8>;

    /// Deserialize diff from wire format.
    fn decode_diff(data: &[u8]) -> Result<Self::Diff, DecodeError>;

    /// Check if diff is empty (optimization for ack-only).
    ///
    /// Returns `true` if the diff represents no change.
    fn is_diff_empty(diff: &Self::Diff) -> bool {
        let _ = diff;
        false
    }
}

/// Optional trait for states that support client-side prediction.
///
/// See 4-EXTENSIONS.md for prediction specification.
pub trait Predictable: SyncState {
    /// User input type (e.g., keystrokes).
    type Input;

    /// Apply speculative input locally.
    fn predict(&mut self, input: &Self::Input);

    /// Reconcile with authoritative server state.
    fn reconcile(&mut self, authoritative: &Self);
}
