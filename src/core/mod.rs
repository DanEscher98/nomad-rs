//! NOMAD Protocol - Core traits, types, and constants.
//!
//! This module provides the foundational traits and types for the NOMAD protocol.
//! It has minimal dependencies and defines the core abstractions.

mod constants;
mod error;
mod traits;

pub use constants::*;
pub use error::*;
pub use traits::*;
