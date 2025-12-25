// NOMAD Protocol - Contracts
//
// These files define the shared types and interfaces that all tentacles must follow.
// They serve as the single source of truth for the protocol implementation.
//
// Tentacles should copy the relevant types to their crates during implementation,
// ensuring they match these contracts exactly.

pub mod constants;
pub mod errors;
pub mod frames;
pub mod messages;
pub mod traits;

// Re-exports for convenience
pub use constants::*;
pub use errors::*;
pub use frames::*;
pub use messages::SyncMessage;
pub use traits::{Predictable, SyncState};
