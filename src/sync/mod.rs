//! NOMAD Protocol - Sync Layer
//!
//! Implements:
//! - State versioning with monotonic version numbers
//! - Idempotent diff generation and application
//! - Acknowledgment tracking
//! - Eventual consistency guarantees

mod ack;
mod engine;
mod message;
mod receiver;
mod sender;
mod tracker;

pub use ack::*;
pub use engine::*;
pub use message::*;
pub use receiver::*;
pub use sender::*;
pub use tracker::*;
