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
//! - `full` (default): Include all features
//! - `transport`: Transport layer (frames, RTT, pacing)
//! - `sync`: Sync layer (state versioning, diffs)
//! - `extensions`: Protocol extensions (compression)
//! - `client`: High-level client API
//! - `server`: High-level server API
//! - `compression`: Enable zstd compression
//!
//! ## Example Usage
//!
//! ```rust,ignore
//! use nomad::prelude::*;
//!
//! // Define your state type
//! #[derive(Clone)]
//! struct MyState { /* ... */ }
//!
//! impl SyncState for MyState {
//!     type Diff = MyDiff;
//!     const STATE_TYPE_ID: &'static str = "com.example.myapp.v1";
//!     // ... implement trait methods
//! }
//! ```
//!
//! ## Crate Organization
//!
//! - [`core`]: Core traits and types (always included)
//! - [`crypto`]: Cryptographic primitives (always included)
//! - [`transport`]: Transport layer (requires `transport` feature)
//! - [`sync`]: Sync layer (requires `sync` feature)
//! - [`extensions`]: Protocol extensions (requires `extensions` feature)
//! - [`client`]: High-level client API (requires `client` feature)
//! - [`server`]: High-level server API (requires `server` feature)

#![forbid(unsafe_code)]
#![cfg_attr(docsrs, feature(doc_cfg))]

// Core (always included)
pub use nomad_core as core;
pub use nomad_crypto as crypto;

// Optional layers
#[cfg(feature = "transport")]
#[cfg_attr(docsrs, doc(cfg(feature = "transport")))]
pub use nomad_transport as transport;

#[cfg(feature = "sync")]
#[cfg_attr(docsrs, doc(cfg(feature = "sync")))]
pub use nomad_sync as sync;

#[cfg(feature = "extensions")]
#[cfg_attr(docsrs, doc(cfg(feature = "extensions")))]
pub use nomad_extensions as extensions;

#[cfg(feature = "client")]
#[cfg_attr(docsrs, doc(cfg(feature = "client")))]
pub use nomad_client as client;

#[cfg(feature = "server")]
#[cfg_attr(docsrs, doc(cfg(feature = "server")))]
pub use nomad_server as server;

/// Prelude module for convenient imports.
pub mod prelude {
    // Core traits
    pub use nomad_core::*;

    // Crypto types commonly needed
    pub use nomad_crypto::*;

    // Transport types
    #[cfg(feature = "transport")]
    pub use nomad_transport::*;

    // Sync types
    #[cfg(feature = "sync")]
    pub use nomad_sync::*;

    // Extension types
    #[cfg(feature = "extensions")]
    pub use nomad_extensions::*;

    // Client types
    #[cfg(feature = "client")]
    pub use nomad_client::*;

    // Server types
    #[cfg(feature = "server")]
    pub use nomad_server::*;
}
