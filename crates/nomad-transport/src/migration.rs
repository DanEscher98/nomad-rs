//! Connection migration (roaming) support.
//!
//! Implements seamless IP address changes from 2-TRANSPORT.md.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

/// Migration rate limiting constants.
pub mod constants {
    use std::time::Duration;

    /// Minimum time between migrations from different subnets.
    pub const MIN_MIGRATION_INTERVAL: Duration = Duration::from_secs(1);

    /// Maximum bytes to send to unvalidated address (anti-amplification).
    pub const AMPLIFICATION_FACTOR: usize = 3;
}

/// Tracks the validation state of an address.
#[derive(Debug, Clone)]
struct AddressState {
    /// When we first saw this address.
    first_seen: Instant,
    /// Total bytes received from this address.
    bytes_received: usize,
    /// Total bytes sent to this address.
    bytes_sent: usize,
    /// Whether this address is validated (received authenticated frame).
    validated: bool,
}

impl AddressState {
    fn new() -> Self {
        Self {
            first_seen: Instant::now(),
            bytes_received: 0,
            bytes_sent: 0,
            validated: false,
        }
    }
}

/// Extract subnet key for rate limiting.
/// Uses /24 for IPv4 and /48 for IPv6.
fn subnet_key(addr: &IpAddr) -> Vec<u8> {
    match addr {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            vec![octets[0], octets[1], octets[2]] // /24
        }
        IpAddr::V6(v6) => {
            let segments = v6.segments();
            // /48 = first 3 segments (48 bits)
            let mut key = Vec::with_capacity(6);
            for seg in &segments[0..3] {
                key.extend_from_slice(&seg.to_be_bytes());
            }
            key
        }
    }
}

/// Migration state tracker.
///
/// Handles:
/// - Address validation
/// - Anti-amplification limiting
/// - Migration rate limiting
#[derive(Debug)]
pub struct MigrationState {
    /// The current validated remote address.
    current_address: SocketAddr,
    /// Tracking state for addresses.
    addresses: HashMap<SocketAddr, AddressState>,
    /// Last migration time per subnet (for rate limiting).
    subnet_last_migration: HashMap<Vec<u8>, Instant>,
}

impl MigrationState {
    /// Create a new migration state with the initial address.
    pub fn new(initial_address: SocketAddr) -> Self {
        let mut addresses = HashMap::new();
        let mut state = AddressState::new();
        state.validated = true; // Initial address is pre-validated
        addresses.insert(initial_address, state);

        Self {
            current_address: initial_address,
            addresses,
            subnet_last_migration: HashMap::new(),
        }
    }

    /// Get the current validated address.
    pub fn current_address(&self) -> SocketAddr {
        self.current_address
    }

    /// Record bytes received from an address.
    pub fn on_receive(&mut self, from: SocketAddr, bytes: usize) {
        let state = self.addresses.entry(from).or_insert_with(AddressState::new);
        state.bytes_received = state.bytes_received.saturating_add(bytes);
    }

    /// Record bytes sent to an address.
    pub fn on_send(&mut self, to: SocketAddr, bytes: usize) {
        if let Some(state) = self.addresses.get_mut(&to) {
            state.bytes_sent = state.bytes_sent.saturating_add(bytes);
        }
    }

    /// Check if we can send bytes to an unvalidated address (anti-amplification).
    pub fn can_send(&self, to: SocketAddr, bytes: usize) -> bool {
        if let Some(state) = self.addresses.get(&to) {
            if state.validated {
                return true;
            }
            // Check amplification limit: can't send more than 3x received
            let allowed = state.bytes_received.saturating_mul(constants::AMPLIFICATION_FACTOR);
            state.bytes_sent.saturating_add(bytes) <= allowed
        } else {
            // Unknown address - can't send anything until we receive first
            false
        }
    }

    /// Validate an address after receiving an authenticated frame from it.
    ///
    /// Returns true if migration to this address is allowed.
    pub fn validate_address(&mut self, addr: SocketAddr) -> bool {
        // Check rate limiting for different subnets
        if addr != self.current_address {
            let current_subnet = subnet_key(&self.current_address.ip());
            let new_subnet = subnet_key(&addr.ip());

            if current_subnet != new_subnet {
                let now = Instant::now();
                if let Some(&last) = self.subnet_last_migration.get(&new_subnet)
                    && now.duration_since(last) < constants::MIN_MIGRATION_INTERVAL
                {
                    return false; // Rate limited
                }
                self.subnet_last_migration.insert(new_subnet, now);
            }
        }

        // Mark address as validated
        let state = self.addresses.entry(addr).or_insert_with(AddressState::new);
        state.validated = true;

        // Update current address
        self.current_address = addr;

        true
    }

    /// Check if an address is validated.
    pub fn is_validated(&self, addr: SocketAddr) -> bool {
        self.addresses
            .get(&addr)
            .is_some_and(|state| state.validated)
    }

    /// Clean up old address entries.
    pub fn cleanup(&mut self, max_age: Duration) {
        let now = Instant::now();
        self.addresses.retain(|addr, state| {
            // Keep current address and recently seen addresses
            *addr == self.current_address || now.duration_since(state.first_seen) < max_age
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    fn addr_v4(a: u8, b: u8, c: u8, d: u8, port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(a, b, c, d)), port)
    }

    #[allow(dead_code)]
    fn addr_v6(segments: [u16; 8], port: u16) -> SocketAddr {
        SocketAddr::new(
            IpAddr::V6(Ipv6Addr::new(
                segments[0],
                segments[1],
                segments[2],
                segments[3],
                segments[4],
                segments[5],
                segments[6],
                segments[7],
            )),
            port,
        )
    }

    #[test]
    fn test_migration_state_initial() {
        let addr = addr_v4(192, 168, 1, 100, 8080);
        let state = MigrationState::new(addr);

        assert_eq!(state.current_address(), addr);
        assert!(state.is_validated(addr));
    }

    #[test]
    fn test_anti_amplification() {
        let initial = addr_v4(192, 168, 1, 100, 8080);
        let mut state = MigrationState::new(initial);

        let new_addr = addr_v4(10, 0, 0, 50, 9090);

        // Can't send to unknown address
        assert!(!state.can_send(new_addr, 100));

        // Receive some bytes
        state.on_receive(new_addr, 100);

        // Can send up to 3x
        assert!(state.can_send(new_addr, 300));
        assert!(!state.can_send(new_addr, 301));

        // After validation, no limit
        state.validate_address(new_addr);
        assert!(state.can_send(new_addr, 10000));
    }

    #[test]
    fn test_migration_same_subnet() {
        let initial = addr_v4(192, 168, 1, 100, 8080);
        let mut state = MigrationState::new(initial);

        // Same /24 subnet - should not be rate limited
        let new_addr = addr_v4(192, 168, 1, 200, 9090);
        assert!(state.validate_address(new_addr));
        assert_eq!(state.current_address(), new_addr);
    }

    #[test]
    fn test_migration_different_subnet_rate_limit() {
        let initial = addr_v4(192, 168, 1, 100, 8080);
        let mut state = MigrationState::new(initial);

        // Different /24 subnet
        let new_addr = addr_v4(10, 0, 0, 50, 9090);
        assert!(state.validate_address(new_addr));

        // Try to migrate to another different subnet immediately
        let another_addr = addr_v4(172, 16, 0, 1, 7070);
        // This should work since it's a different subnet from new_addr
        assert!(state.validate_address(another_addr));
    }

    #[test]
    fn test_subnet_key_v4() {
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        let key = subnet_key(&ip);
        assert_eq!(key, vec![192, 168, 1]);
    }

    #[test]
    fn test_subnet_key_v6() {
        let ip = IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0x85a3, 0, 0, 0, 0, 1));
        let key = subnet_key(&ip);
        // /48 = first 3 segments = 6 bytes
        assert_eq!(key.len(), 6);
        assert_eq!(&key[0..2], &[0x20, 0x01]);
        assert_eq!(&key[2..4], &[0x0d, 0xb8]);
        assert_eq!(&key[4..6], &[0x85, 0xa3]);
    }

    #[test]
    fn test_cleanup() {
        let initial = addr_v4(192, 168, 1, 100, 8080);
        let mut state = MigrationState::new(initial);

        // Add another address
        let other = addr_v4(10, 0, 0, 50, 9090);
        state.on_receive(other, 100);

        // Cleanup with very short max age shouldn't remove current
        state.cleanup(Duration::from_nanos(1));
        assert!(state.is_validated(initial));
    }
}
