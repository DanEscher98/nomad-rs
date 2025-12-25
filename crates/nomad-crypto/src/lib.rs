//! NOMAD Protocol - Security Layer
//!
//! Implements the cryptographic primitives for NOMAD:
//! - Noise_IK handshake
//! - XChaCha20-Poly1305 AEAD
//! - Nonce construction
//! - Anti-replay protection
//! - Rekeying

#![forbid(unsafe_code)]

mod aead;
mod keys;
mod noise;
mod nonce;
mod rekey;
mod session;

pub use aead::*;
pub use keys::*;
pub use noise::*;
pub use nonce::*;
pub use rekey::*;
pub use session::*;
