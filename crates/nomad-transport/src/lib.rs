//! NOMAD Protocol - Transport Layer
//!
//! Implements:
//! - Frame encoding/decoding
//! - Connection state machine
//! - RTT estimation (RFC 6298)
//! - Frame pacing
//! - Connection migration (roaming)

#![forbid(unsafe_code)]

mod connection;
mod frame;
mod migration;
mod pacing;
mod socket;
mod timing;

pub use connection::*;
pub use frame::*;
pub use migration::*;
pub use pacing::*;
pub use socket::*;
pub use timing::*;
