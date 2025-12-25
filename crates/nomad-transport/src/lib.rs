//! NOMAD Protocol - Transport Layer
//!
//! This crate implements the transport layer of the NOMAD protocol as specified
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
//! The transport layer sits between the security layer (nomad-crypto) and the
//! sync layer (nomad-sync). It handles frame framing, timing, and connection
//! management while remaining agnostic to the encrypted payload contents.
//!
//! ```text
//! ┌─────────────────────────────────────────┐
//! │            Sync Layer                   │
//! │         (nomad-sync)                    │
//! ├─────────────────────────────────────────┤
//! │         Transport Layer                 │  ← This crate
//! │   frames, RTT, pacing, migration        │
//! ├─────────────────────────────────────────┤
//! │         Security Layer                  │
//! │        (nomad-crypto)                   │
//! ├─────────────────────────────────────────┤
//! │              UDP                        │
//! └─────────────────────────────────────────┘
//! ```
//!
//! # Key Types
//!
//! - [`SessionId`]: 6-byte session identifier from handshake
//! - [`DataFrameHeader`]: Unencrypted frame header (used as AAD)
//! - [`PayloadHeader`]: Encrypted payload header with timestamps
//! - [`ConnectionState`]: Full connection state including all sub-components
//!
//! # Timing
//!
//! All timing constants are defined in [`timing::constants`] and [`pacing::constants`]:
//!
//! | Constant | Value | Description |
//! |----------|-------|-------------|
//! | `INITIAL_RTO` | 1000ms | Initial retransmission timeout |
//! | `MIN_RTO` | 100ms | Minimum RTO |
//! | `MAX_RTO` | 60000ms | Maximum RTO |
//! | `COLLECTION_INTERVAL` | 8ms | Batch rapid state changes |
//! | `DELAYED_ACK_TIMEOUT` | 100ms | Max ACK delay |
//! | `KEEPALIVE_INTERVAL` | 25s | Keepalive if idle |
//! | `DEAD_INTERVAL` | 60s | Connection timeout |

#![forbid(unsafe_code)]
#![warn(missing_docs)]

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
