//! Connection state management for NOMAD transport layer.
//!
//! Implements the connection state machine from 2-TRANSPORT.md.

use std::net::SocketAddr;
use std::time::Instant;

use super::frame::SessionId;
use super::migration::MigrationState;
use super::pacing::{FramePacer, RetransmitController};
use super::timing::{RttEstimator, TimestampTracker};

/// Connection lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionPhase {
    /// Handshake in progress.
    Handshaking,
    /// Connection established, data transfer active.
    Established,
    /// Connection closing gracefully.
    Closing,
    /// Connection closed.
    Closed,
    /// Connection failed (timeout, too many retransmits, etc).
    Failed,
}

/// Anti-replay window using a bitfield.
///
/// Tracks received nonces to detect and reject replayed frames.
/// Uses a sliding window of 2048+ bits as recommended by the spec.
#[derive(Debug, Clone)]
pub struct NonceWindow {
    /// The highest nonce we've seen.
    highest: u64,
    /// Bitfield for nonces below highest (bit i = highest - 1 - i).
    /// We track 2048 nonces below the highest.
    window: [u64; 32], // 32 * 64 = 2048 bits
}

impl Default for NonceWindow {
    fn default() -> Self {
        Self::new()
    }
}

impl NonceWindow {
    /// Window size in bits.
    pub const WINDOW_SIZE: usize = 2048;

    /// Create a new nonce window.
    pub fn new() -> Self {
        Self {
            highest: 0,
            window: [0; 32],
        }
    }

    /// Check if a nonce is valid (not replayed) and mark it as seen.
    ///
    /// Returns `true` if the nonce is valid and should be accepted,
    /// `false` if it's a replay or too old.
    pub fn check_and_mark(&mut self, nonce: u64) -> bool {
        // First nonce ever
        if self.highest == 0 && nonce > 0 {
            self.highest = nonce;
            return true;
        }

        if nonce > self.highest {
            // New highest nonce - shift window
            let shift = (nonce - self.highest) as usize;
            self.shift_window(shift);
            self.highest = nonce;
            true
        } else if nonce == self.highest {
            // Duplicate of the highest
            false
        } else {
            // Nonce below highest - check window
            let offset = (self.highest - nonce) as usize;
            if offset > Self::WINDOW_SIZE {
                // Too old, outside our window
                return false;
            }

            let offset = offset - 1; // Convert to 0-indexed
            let word_idx = offset / 64;
            let bit_idx = offset % 64;
            let mask = 1u64 << bit_idx;

            if self.window[word_idx] & mask != 0 {
                // Already seen
                false
            } else {
                // Mark as seen
                self.window[word_idx] |= mask;
                true
            }
        }
    }

    /// Shift the window by the given amount.
    fn shift_window(&mut self, shift: usize) {
        if shift >= Self::WINDOW_SIZE {
            // Complete reset
            self.window = [0; 32];
            return;
        }

        let word_shift = shift / 64;
        let bit_shift = shift % 64;

        if word_shift > 0 {
            // Shift words
            for i in (word_shift..32).rev() {
                self.window[i] = self.window[i - word_shift];
            }
            for i in 0..word_shift {
                self.window[i] = 0;
            }
        }

        if bit_shift > 0 {
            // Shift bits within words
            let mut carry = 0u64;
            for i in (0..32).rev() {
                let new_carry = self.window[i] << (64 - bit_shift);
                self.window[i] = (self.window[i] >> bit_shift) | carry;
                carry = new_carry;
            }
        }

        // Mark the old highest as seen (it's now at offset 'shift - 1')
        if shift > 0 {
            let offset = shift - 1;
            if offset < Self::WINDOW_SIZE {
                let word_idx = offset / 64;
                let bit_idx = offset % 64;
                self.window[word_idx] |= 1u64 << bit_idx;
            }
        }
    }
}

/// Full connection state as specified in 2-TRANSPORT.md.
#[derive(Debug)]
pub struct ConnectionState {
    /// Session identifier from handshake.
    pub session_id: SessionId,
    /// Current connection phase.
    pub phase: ConnectionPhase,
    /// Remote peer address (may change during migration).
    pub remote_endpoint: SocketAddr,
    /// When we last received an authenticated frame.
    pub last_received: Instant,
    /// Current epoch (increments on rekey).
    pub epoch: u32,

    /// Outbound nonce counter (monotonically increasing).
    pub send_nonce: u64,
    /// Inbound anti-replay window.
    pub recv_nonce_window: NonceWindow,

    /// RTT estimation.
    pub rtt: RttEstimator,
    /// Timestamp tracking for RTT measurement.
    pub timestamps: TimestampTracker,
    /// Frame pacing.
    pub pacer: FramePacer,
    /// Retransmission control.
    pub retransmit: RetransmitController,
    /// Migration state.
    pub migration: MigrationState,

    /// Highest state version we've sent.
    pub local_state_version: u64,
    /// Highest state version we've acknowledged from peer.
    pub remote_state_version: u64,
    /// Highest state version the peer has acknowledged from us.
    pub acked_state_version: u64,
}

impl ConnectionState {
    /// Create a new connection state for an established session.
    pub fn new(session_id: SessionId, remote_endpoint: SocketAddr) -> Self {
        let now = Instant::now();
        Self {
            session_id,
            phase: ConnectionPhase::Established,
            remote_endpoint,
            last_received: now,
            epoch: 0,

            send_nonce: 0,
            recv_nonce_window: NonceWindow::new(),

            rtt: RttEstimator::new(),
            timestamps: TimestampTracker::new(),
            pacer: FramePacer::new(),
            retransmit: RetransmitController::new(super::timing::constants::INITIAL_RTO),
            migration: MigrationState::new(remote_endpoint),

            local_state_version: 0,
            remote_state_version: 0,
            acked_state_version: 0,
        }
    }

    /// Create a connection state in handshaking phase.
    pub fn handshaking(remote_endpoint: SocketAddr) -> Self {
        let now = Instant::now();
        Self {
            session_id: SessionId::zero(),
            phase: ConnectionPhase::Handshaking,
            remote_endpoint,
            last_received: now,
            epoch: 0,

            send_nonce: 0,
            recv_nonce_window: NonceWindow::new(),

            rtt: RttEstimator::new(),
            timestamps: TimestampTracker::new(),
            pacer: FramePacer::new(),
            retransmit: RetransmitController::new(super::timing::constants::INITIAL_RTO),
            migration: MigrationState::new(remote_endpoint),

            local_state_version: 0,
            remote_state_version: 0,
            acked_state_version: 0,
        }
    }

    /// Get the next nonce for sending and increment the counter.
    pub fn next_send_nonce(&mut self) -> u64 {
        let nonce = self.send_nonce;
        self.send_nonce = self.send_nonce.saturating_add(1);
        nonce
    }

    /// Check if a received nonce is valid (not replayed).
    pub fn check_recv_nonce(&mut self, nonce: u64) -> bool {
        self.recv_nonce_window.check_and_mark(nonce)
    }

    /// Update state after receiving an authenticated frame.
    pub fn on_authenticated_frame(&mut self, from: SocketAddr) {
        self.last_received = Instant::now();

        // Handle potential migration
        if from != self.remote_endpoint && self.migration.validate_address(from) {
            self.remote_endpoint = from;
        }
    }

    /// Check if the connection is still alive.
    pub fn is_alive(&self) -> bool {
        !self.pacer.is_connection_dead(self.last_received) && !self.retransmit.is_failed()
    }

    /// Check if the connection has failed.
    pub fn is_failed(&self) -> bool {
        self.phase == ConnectionPhase::Failed
            || self.pacer.is_connection_dead(self.last_received)
            || self.retransmit.is_failed()
    }

    /// Check if there's unacknowledged data.
    pub fn has_unacked_data(&self) -> bool {
        self.local_state_version > self.acked_state_version
    }

    /// Update the acked state version.
    pub fn on_ack(&mut self, acked_version: u64) {
        if acked_version > self.acked_state_version {
            self.acked_state_version = acked_version;
            self.retransmit.on_ack();
        }
    }

    /// Transition to closed state.
    pub fn close(&mut self) {
        self.phase = ConnectionPhase::Closing;
    }

    /// Mark as fully closed.
    pub fn mark_closed(&mut self) {
        self.phase = ConnectionPhase::Closed;
    }

    /// Mark as failed.
    pub fn mark_failed(&mut self) {
        self.phase = ConnectionPhase::Failed;
    }

    /// Complete handshake and transition to established.
    pub fn complete_handshake(&mut self, session_id: SessionId) {
        self.session_id = session_id;
        self.phase = ConnectionPhase::Established;
        self.timestamps = TimestampTracker::new(); // Reset timestamps
    }

    /// Increment epoch (on rekey).
    pub fn on_rekey(&mut self) {
        self.epoch = self.epoch.saturating_add(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn test_addr(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port)
    }

    #[test]
    fn test_nonce_window_new() {
        let mut window = NonceWindow::new();

        // First nonce should be accepted
        assert!(window.check_and_mark(1));

        // Same nonce should be rejected
        assert!(!window.check_and_mark(1));

        // Next nonce should be accepted
        assert!(window.check_and_mark(2));
    }

    #[test]
    fn test_nonce_window_gap() {
        let mut window = NonceWindow::new();

        // Accept nonce 1
        assert!(window.check_and_mark(1));

        // Skip to nonce 100
        assert!(window.check_and_mark(100));

        // Nonces in between should still be valid (not seen)
        assert!(window.check_and_mark(50));
        assert!(window.check_and_mark(75));

        // But duplicates should be rejected
        assert!(!window.check_and_mark(50));
        assert!(!window.check_and_mark(100));
    }

    #[test]
    fn test_nonce_window_too_old() {
        let mut window = NonceWindow::new();

        // Accept high nonce
        assert!(window.check_and_mark(3000));

        // Very old nonce should be rejected (outside window)
        assert!(!window.check_and_mark(1));
        assert!(!window.check_and_mark(500)); // 3000 - 500 = 2500 > 2048
    }

    #[test]
    fn test_connection_state_nonces() {
        let mut conn = ConnectionState::new(SessionId::zero(), test_addr(8080));

        // Get sequential nonces
        assert_eq!(conn.next_send_nonce(), 0);
        assert_eq!(conn.next_send_nonce(), 1);
        assert_eq!(conn.next_send_nonce(), 2);

        // Verify nonce counter
        assert_eq!(conn.send_nonce, 3);
    }

    #[test]
    fn test_connection_state_lifecycle() {
        let addr = test_addr(8080);
        let mut conn = ConnectionState::handshaking(addr);

        assert_eq!(conn.phase, ConnectionPhase::Handshaking);

        // Complete handshake
        let session_id = SessionId::from_bytes([1, 2, 3, 4, 5, 6]);
        conn.complete_handshake(session_id);
        assert_eq!(conn.phase, ConnectionPhase::Established);
        assert_eq!(conn.session_id, session_id);

        // Close
        conn.close();
        assert_eq!(conn.phase, ConnectionPhase::Closing);

        conn.mark_closed();
        assert_eq!(conn.phase, ConnectionPhase::Closed);
    }

    #[test]
    fn test_connection_state_ack() {
        let mut conn = ConnectionState::new(SessionId::zero(), test_addr(8080));

        conn.local_state_version = 10;
        assert!(conn.has_unacked_data());

        conn.on_ack(5);
        assert_eq!(conn.acked_state_version, 5);
        assert!(conn.has_unacked_data());

        conn.on_ack(10);
        assert_eq!(conn.acked_state_version, 10);
        assert!(!conn.has_unacked_data());
    }

    #[test]
    fn test_connection_alive_check() {
        let conn = ConnectionState::new(SessionId::zero(), test_addr(8080));
        assert!(conn.is_alive());
        assert!(!conn.is_failed());
    }
}
