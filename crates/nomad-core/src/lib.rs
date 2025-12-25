//! NOMAD Protocol - Core traits and types
//!
//! This crate provides the foundational traits and types for the NOMAD protocol.
//! It has no I/O dependencies and can be used in `#![no_std]` environments.

#![forbid(unsafe_code)]

mod constants;
mod error;
mod traits;

pub use constants::*;
pub use error::*;
pub use traits::*;
