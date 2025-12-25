//! # NOMAD Protocol
//!
//! **N**etwork-**O**ptimized **M**obile **A**pplication **D**atagram
//!
//! NOMAD is a secure, UDP-based state synchronization protocol designed for
//! real-time applications over unreliable networks. It provides:
//!
//! - **Security**: End-to-end authenticated encryption with forward secrecy
//! - **Mobility**: Seamless operation across IP address changes (roaming)
//! - **Latency**: Sub-100ms reconnection, optional client-side prediction
//! - **Simplicity**: Fixed cryptographic suite, no negotiation
//! - **Generality**: State-agnostic synchronization framework
//!
//! ## Feature Flags
//!
//! - `transport` (default): Transport layer (frames, RTT, pacing, sockets)
//! - `crypto` (default): Security layer (Noise_IK, XChaCha20-Poly1305)
//!
//! ## Modules
//!
//! - [`core`]: Core traits, constants, and error types (always included)
//! - [`transport`]: Transport layer (requires `transport` feature)
//! - [`crypto`]: Security layer (requires `crypto` feature)
//!
//! ## Example Usage
//!
//! ```rust
//! use nomad_protocol::prelude::*;
//!
//! // Define your state type
//! #[derive(Clone)]
//! struct MyState {
//!     counter: u64,
//! }
//!
//! #[derive(Clone)]
//! struct MyDiff {
//!     delta: i64,
//! }
//!
//! impl SyncState for MyState {
//!     type Diff = MyDiff;
//!     const STATE_TYPE_ID: &'static str = "example.counter.v1";
//!
//!     fn diff_from(&self, old: &Self) -> Self::Diff {
//!         MyDiff {
//!             delta: self.counter as i64 - old.counter as i64,
//!         }
//!     }
//!
//!     fn apply_diff(&mut self, diff: &Self::Diff) -> Result<(), ApplyError> {
//!         self.counter = (self.counter as i64 + diff.delta) as u64;
//!         Ok(())
//!     }
//!
//!     fn encode_diff(diff: &Self::Diff) -> Vec<u8> {
//!         diff.delta.to_le_bytes().to_vec()
//!     }
//!
//!     fn decode_diff(data: &[u8]) -> Result<Self::Diff, DecodeError> {
//!         if data.len() < 8 {
//!             return Err(DecodeError::UnexpectedEof);
//!         }
//!         let delta = i64::from_le_bytes(data[..8].try_into().unwrap());
//!         Ok(MyDiff { delta })
//!     }
//! }
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![cfg_attr(docsrs, feature(doc_cfg))]

// Core module (always included)
pub mod core;

// Transport layer (feature-gated)
#[cfg(feature = "transport")]
#[cfg_attr(docsrs, doc(cfg(feature = "transport")))]
pub mod transport;

// Crypto layer (feature-gated)
#[cfg(feature = "crypto")]
#[cfg_attr(docsrs, doc(cfg(feature = "crypto")))]
pub mod crypto;

// Sync layer (feature-gated)
#[cfg(feature = "sync")]
#[cfg_attr(docsrs, doc(cfg(feature = "sync")))]
pub mod sync;

// Extensions (feature-gated)
#[cfg(feature = "extensions")]
#[cfg_attr(docsrs, doc(cfg(feature = "extensions")))]
pub mod extensions;

// Client API (feature-gated)
#[cfg(feature = "client")]
#[cfg_attr(docsrs, doc(cfg(feature = "client")))]
pub mod client;

// Server API (feature-gated)
#[cfg(feature = "server")]
#[cfg_attr(docsrs, doc(cfg(feature = "server")))]
pub mod server;

/// Prelude module for convenient imports.
pub mod prelude {
    // Core traits and types
    pub use crate::core::*;

    // Transport types (when enabled) - exclude SessionId to avoid conflict with crypto
    #[cfg(feature = "transport")]
    pub use crate::transport::{
        ConnectionPhase, ConnectionState, DataFrame, DataFrameHeader, FrameFlags, FramePacer,
        FrameType, MigrationState, NomadSocket, NomadSocketBuilder, PacerAction,
        PayloadHeader, RetransmitController, RttEstimator, SendReason, TimestampTracker,
        TransportError, TransportResult,
    };

    // Crypto types (when enabled) - SessionId comes from here
    #[cfg(feature = "crypto")]
    pub use crate::crypto::*;
}

// Re-export commonly used items at crate root
pub use core::{ApplyError, DecodeError, NomadError, SyncState};

#[cfg(feature = "transport")]
pub use transport::{
    ConnectionPhase, ConnectionState, DataFrame, DataFrameHeader, FrameFlags, FramePacer,
    FrameType, NomadSocket, PayloadHeader, RttEstimator, SessionId,
};
