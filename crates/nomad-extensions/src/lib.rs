//! NOMAD Protocol - Extensions
//!
//! Implements optional protocol extensions:
//! - Compression (zstd)
//!
//! Note: Terminal-specific extensions (scrollback, prediction) are
//! NOT implemented here - they belong in nomad-terminal.

#![forbid(unsafe_code)]

#[cfg(feature = "compression")]
mod compression;

mod negotiation;

#[cfg(feature = "compression")]
pub use compression::*;
pub use negotiation::*;
