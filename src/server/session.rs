//! Server session management.
//!
//! Handles per-client session state including:
//! - Session ID management
//! - State synchronization tracking
//! - Session lifecycle

use std::net::SocketAddr;
use std::time::Instant;

use crate::core::SyncState;

/// Session ID (48-bit, as per NOMAD spec).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ServerSessionId([u8; 6]);

impl ServerSessionId {
    /// Create a new session ID from bytes.
    pub fn new(bytes: [u8; 6]) -> Self {
        Self(bytes)
    }

    /// Generate a random session ID.
    pub fn generate() -> Self {
        // TODO: Use proper crypto RNG from crypto module
        use std::time::{SystemTime, UNIX_EPOCH};

        let seed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;

        let mut id = [0u8; 6];
        let mut state = seed;
        for byte in &mut id {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            *byte = (state >> 33) as u8;
        }

        Self(id)
    }

    /// Get the session ID as bytes.
    pub fn as_bytes(&self) -> &[u8; 6] {
        &self.0
    }

    /// Convert to a u64 (zero-padded).
    pub fn to_u64(&self) -> u64 {
        let mut buf = [0u8; 8];
        buf[..6].copy_from_slice(&self.0);
        u64::from_le_bytes(buf)
    }
}

impl std::fmt::Display for ServerSessionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:012x}", self.to_u64())
    }
}

impl From<[u8; 6]> for ServerSessionId {
    fn from(bytes: [u8; 6]) -> Self {
        Self::new(bytes)
    }
}

impl From<ServerSessionId> for [u8; 6] {
    fn from(id: ServerSessionId) -> [u8; 6] {
        id.0
    }
}

/// Session state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    /// Handshake in progress.
    Handshaking,
    /// Session is active and syncing.
    Active,
    /// Session is closing.
    Closing,
    /// Session is closed.
    Closed,
}

/// Per-client session.
#[derive(Debug)]
pub struct ServerSession<S: SyncState> {
    /// Session ID.
    id: ServerSessionId,

    /// Client's address.
    client_addr: SocketAddr,

    /// Client's static public key.
    client_public_key: [u8; 32],

    /// Session state.
    state: SessionState,

    /// Current server-side state.
    server_state: S,

    /// Last known client state version.
    client_state_version: u64,

    /// Last known server state version.
    server_state_version: u64,

    /// Last activity time.
    last_activity: Instant,

    /// Created time.
    created_at: Instant,

    /// Negotiated extensions.
    extensions: Vec<u16>,
}

impl<S: SyncState> ServerSession<S> {
    /// Create a new session.
    pub fn new(
        id: ServerSessionId,
        client_addr: SocketAddr,
        client_public_key: [u8; 32],
        initial_state: S,
    ) -> Self {
        let now = Instant::now();
        Self {
            id,
            client_addr,
            client_public_key,
            state: SessionState::Handshaking,
            server_state: initial_state,
            client_state_version: 0,
            server_state_version: 0,
            last_activity: now,
            created_at: now,
            extensions: Vec::new(),
        }
    }

    /// Get the session ID.
    pub fn id(&self) -> ServerSessionId {
        self.id
    }

    /// Get the client address.
    pub fn client_addr(&self) -> SocketAddr {
        self.client_addr
    }

    /// Get the client's public key.
    pub fn client_public_key(&self) -> &[u8; 32] {
        &self.client_public_key
    }

    /// Get the session state.
    pub fn state(&self) -> SessionState {
        self.state
    }

    /// Set the session state.
    pub fn set_state(&mut self, state: SessionState) {
        self.state = state;
    }

    /// Get the current server state.
    pub fn server_state(&self) -> &S {
        &self.server_state
    }

    /// Get mutable access to the server state.
    pub fn server_state_mut(&mut self) -> &mut S {
        &mut self.server_state
    }

    /// Update the server state and increment version.
    pub fn update_server_state(&mut self, state: S) {
        self.server_state = state;
        self.server_state_version += 1;
    }

    /// Get the client state version.
    pub fn client_state_version(&self) -> u64 {
        self.client_state_version
    }

    /// Update the client state version (from ack).
    pub fn update_client_state_version(&mut self, version: u64) {
        self.client_state_version = version;
    }

    /// Get the server state version.
    pub fn server_state_version(&self) -> u64 {
        self.server_state_version
    }

    /// Record activity.
    pub fn touch(&mut self) {
        self.last_activity = Instant::now();
    }

    /// Get time since last activity.
    pub fn idle_time(&self) -> std::time::Duration {
        self.last_activity.elapsed()
    }

    /// Get session age.
    pub fn age(&self) -> std::time::Duration {
        self.created_at.elapsed()
    }

    /// Check if session is active.
    pub fn is_active(&self) -> bool {
        self.state == SessionState::Active
    }

    /// Update the client address (for IP roaming).
    pub fn update_client_addr(&mut self, addr: SocketAddr) {
        self.client_addr = addr;
        self.touch();
    }

    /// Set negotiated extensions.
    pub fn set_extensions(&mut self, extensions: Vec<u16>) {
        self.extensions = extensions;
    }

    /// Get negotiated extensions.
    pub fn extensions(&self) -> &[u16] {
        &self.extensions
    }

    /// Check if compression is enabled.
    pub fn compression_enabled(&self) -> bool {
        // Extension 0x0001 is compression
        self.extensions.contains(&0x0001)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_id_generate() {
        let id1 = ServerSessionId::generate();
        let id2 = ServerSessionId::generate();

        // IDs should be different (with very high probability)
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_session_id_display() {
        let id = ServerSessionId::new([0x01, 0x02, 0x03, 0x04, 0x05, 0x06]);
        let display = format!("{}", id);
        assert_eq!(display.len(), 12); // 48 bits = 12 hex chars
    }
}
