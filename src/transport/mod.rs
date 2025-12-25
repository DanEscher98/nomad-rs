//! NOMAD Protocol - Transport Layer
//!
//! This module implements the transport layer of the NOMAD protocol as specified
//! in 2-TRANSPORT.md. It provides:
//!
//! - **Frame encoding/decoding**: [`DataFrame`], [`CloseFrame`], and wire format handling
//! - **Connection state machine**: [`ConnectionState`] with lifecycle management
//! - **RTT estimation**: [`RttEstimator`] implementing RFC 6298
//! - **Frame pacing**: [`FramePacer`] to prevent buffer bloat
//! - **Connection migration**: [`MigrationState`] for seamless IP roaming
//! - **Async sockets**: [`NomadSocket`] wrapper for tokio UDP
//!
//! # Architecture
//!
//! The transport layer sits between the security layer and the sync layer.
//! It handles frame framing, timing, and connection management while remaining
//! agnostic to the encrypted payload contents.
//!
//! ```text
//! ┌─────────────────────────────────────────┐
//! │            Sync Layer                   │
//! ├─────────────────────────────────────────┤
//! │         Transport Layer                 │  ← This module
//! │   frames, RTT, pacing, migration        │
//! ├─────────────────────────────────────────┤
//! │         Security Layer                  │
//! ├─────────────────────────────────────────┤
//! │              UDP                        │
//! └─────────────────────────────────────────┘
//! ```

mod connection;
mod error;
mod frame;
mod migration;
mod pacing;
mod socket;
mod timing;

pub use connection::*;
pub use error::*;
pub use frame::*;
pub use migration::MigrationState;
pub use pacing::{
    constants as pacing_constants, FramePacer, PacerAction, RetransmitController, SendReason,
};
pub use socket::*;
pub use timing::{constants as timing_constants, RttEstimator, TimestampTracker};
