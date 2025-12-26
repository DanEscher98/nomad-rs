//! NOMAD Protocol - Extensions
//!
//! Implements protocol extensions for enhanced functionality beyond the core sync.
//!
//! ## Core Extensions
//!
//! | ID     | Module          | Description                                      |
//! |--------|-----------------|--------------------------------------------------|
//! | 0x0001 | `compression`   | zstd payload compression                         |
//! | 0x0002 | `priority`      | Update priority levels (critical → background)   |
//! | 0x0003 | `batching`      | Combine multiple updates into single frame       |
//! | 0x0004 | `rate_hints`    | Server hints for acceptable update frequency     |
//! | 0x0005 | `selective_sync`| Subscribe to specific state regions              |
//! | 0x0006 | `checkpoint`    | Full state snapshots for recovery/initial sync   |
//! | 0x0007 | `metadata`      | Timestamps, user IDs, causality tracking         |
//!
//! ## Extension Negotiation
//!
//! Extensions are negotiated during handshake using TLV (Type-Length-Value) format.
//! See [`negotiation`] module for details.
//!
//! ## Reserved Ranges
//!
//! - `0x0001-0x00FF`: Core protocol extensions
//! - `0x0100-0x0FFF`: Application-specific extensions
//! - `0xF000-0xFFFF`: Experimental/private extensions

mod batching;
mod checkpoint;
mod compression;
mod metadata;
mod negotiation;
mod priority;
mod rate_hints;
mod selective_sync;

pub use batching::*;
pub use checkpoint::*;
pub use compression::*;
pub use metadata::*;
pub use negotiation::*;
pub use priority::*;
pub use rate_hints::*;
pub use selective_sync::*;
