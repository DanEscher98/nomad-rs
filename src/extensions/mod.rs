//! NOMAD Protocol - Extensions
//!
//! Implements:
//! - Extension negotiation (TLV format)
//! - zstd compression (extension 0x0001)

mod compression;
mod negotiation;

pub use compression::*;
pub use negotiation::*;
