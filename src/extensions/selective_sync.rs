//! Selective Sync extension (0x0005)
//!
//! Allows clients to subscribe to specific regions of state rather than
//! receiving all updates. Useful for large state spaces where clients
//! only need a subset (e.g., viewport in a document, area in a game world).
//!
//! Wire format for extension negotiation:
//! ```text
//! +0  Flags (1 byte)
//!     - bit 0: Region subscribe/unsubscribe supported
//!     - bit 1: Region expressions supported (patterns)
//!     - bit 2: Nested regions supported
//! +1  Max regions (2 bytes LE16) - maximum concurrent subscriptions
//! +3  Max expression length (2 bytes LE16) - maximum pattern length
//! ```
//!
//! Wire format for subscription change:
//! ```text
//! +0  Operation (1 byte)
//!     - 0x00: Subscribe to region
//!     - 0x01: Unsubscribe from region
//!     - 0x02: Subscribe with pattern
//!     - 0x03: Clear all subscriptions
//! +1  Region spec (variable, based on operation)
//! ```
//!
//! Region spec formats:
//! - Subscribe/Unsubscribe: Region ID (4 bytes LE32)
//! - Pattern: Length (2 bytes LE16) + Pattern bytes

use super::negotiation::{ext_type, Extension, NegotiationError};
use std::collections::HashSet;

/// Selective sync flags
pub mod selective_sync_flags {
    /// Basic region subscribe/unsubscribe
    pub const REGION_OPS: u8 = 0x01;
    /// Pattern-based subscriptions (e.g., "users/*")
    pub const PATTERNS: u8 = 0x02;
    /// Nested/hierarchical regions
    pub const NESTED: u8 = 0x04;
}

/// Selective sync configuration
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectiveSyncConfig {
    /// Feature flags
    pub flags: u8,
    /// Maximum concurrent subscriptions
    pub max_regions: u16,
    /// Maximum pattern length (if patterns supported)
    pub max_expression_len: u16,
}

impl Default for SelectiveSyncConfig {
    fn default() -> Self {
        Self {
            flags: selective_sync_flags::REGION_OPS,
            max_regions: 256,
            max_expression_len: 128,
        }
    }
}

impl SelectiveSyncConfig {
    /// Create config with all features enabled
    pub fn full() -> Self {
        Self {
            flags: selective_sync_flags::REGION_OPS | selective_sync_flags::PATTERNS | selective_sync_flags::NESTED,
            max_regions: 1024,
            max_expression_len: 256,
        }
    }

    /// Check if region operations are supported
    pub fn supports_regions(&self) -> bool {
        (self.flags & selective_sync_flags::REGION_OPS) != 0
    }

    /// Check if pattern subscriptions are supported
    pub fn supports_patterns(&self) -> bool {
        (self.flags & selective_sync_flags::PATTERNS) != 0
    }

    /// Check if nested regions are supported
    pub fn supports_nested(&self) -> bool {
        (self.flags & selective_sync_flags::NESTED) != 0
    }

    /// Wire size
    pub const fn wire_size() -> usize {
        5 // flags(1) + max_regions(2) + max_expr(2)
    }

    /// Encode to extension
    pub fn to_extension(&self) -> Extension {
        let mut data = Vec::with_capacity(Self::wire_size());
        data.push(self.flags);
        data.extend_from_slice(&self.max_regions.to_le_bytes());
        data.extend_from_slice(&self.max_expression_len.to_le_bytes());
        Extension::new(ext_type::SELECTIVE_SYNC, data)
    }

    /// Decode from extension
    pub fn from_extension(ext: &Extension) -> Option<Self> {
        if ext.ext_type != ext_type::SELECTIVE_SYNC || ext.data.len() < Self::wire_size() {
            return None;
        }
        Some(Self {
            flags: ext.data[0],
            max_regions: u16::from_le_bytes([ext.data[1], ext.data[2]]),
            max_expression_len: u16::from_le_bytes([ext.data[3], ext.data[4]]),
        })
    }

    /// Negotiate between client and server
    pub fn negotiate(client: &Self, server: &Self) -> Self {
        Self {
            flags: client.flags & server.flags,
            max_regions: client.max_regions.min(server.max_regions),
            max_expression_len: client.max_expression_len.min(server.max_expression_len),
        }
    }
}

/// Subscription operation type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SubscriptionOp {
    /// Subscribe to a region by ID
    Subscribe = 0x00,
    /// Unsubscribe from a region by ID
    Unsubscribe = 0x01,
    /// Subscribe using a pattern
    SubscribePattern = 0x02,
    /// Clear all subscriptions
    ClearAll = 0x03,
}

impl SubscriptionOp {
    /// Convert from byte
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x00 => Some(Self::Subscribe),
            0x01 => Some(Self::Unsubscribe),
            0x02 => Some(Self::SubscribePattern),
            0x03 => Some(Self::ClearAll),
            _ => None,
        }
    }
}

/// A subscription change request
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubscriptionChange {
    /// Subscribe to a specific region
    Subscribe(u32),
    /// Unsubscribe from a specific region
    Unsubscribe(u32),
    /// Subscribe using a pattern (e.g., "users/*")
    SubscribePattern(String),
    /// Clear all subscriptions
    ClearAll,
}

impl SubscriptionChange {
    /// Wire size
    pub fn wire_size(&self) -> usize {
        match self {
            Self::Subscribe(_) | Self::Unsubscribe(_) => 5, // op(1) + region(4)
            Self::SubscribePattern(p) => 3 + p.len(),       // op(1) + len(2) + pattern
            Self::ClearAll => 1,                            // op(1)
        }
    }

    /// Encode to bytes
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(self.wire_size());
        match self {
            Self::Subscribe(id) => {
                buf.push(SubscriptionOp::Subscribe as u8);
                buf.extend_from_slice(&id.to_le_bytes());
            }
            Self::Unsubscribe(id) => {
                buf.push(SubscriptionOp::Unsubscribe as u8);
                buf.extend_from_slice(&id.to_le_bytes());
            }
            Self::SubscribePattern(pattern) => {
                buf.push(SubscriptionOp::SubscribePattern as u8);
                buf.extend_from_slice(&(pattern.len() as u16).to_le_bytes());
                buf.extend_from_slice(pattern.as_bytes());
            }
            Self::ClearAll => {
                buf.push(SubscriptionOp::ClearAll as u8);
            }
        }
        buf
    }

    /// Decode from bytes
    pub fn decode(data: &[u8]) -> Result<(Self, usize), NegotiationError> {
        if data.is_empty() {
            return Err(NegotiationError::TooShort {
                expected: 1,
                actual: 0,
            });
        }

        let op = SubscriptionOp::from_byte(data[0]).ok_or(NegotiationError::InvalidData)?;

        match op {
            SubscriptionOp::Subscribe | SubscriptionOp::Unsubscribe => {
                if data.len() < 5 {
                    return Err(NegotiationError::TooShort {
                        expected: 5,
                        actual: data.len(),
                    });
                }
                let id = u32::from_le_bytes([data[1], data[2], data[3], data[4]]);
                let change = if op == SubscriptionOp::Subscribe {
                    Self::Subscribe(id)
                } else {
                    Self::Unsubscribe(id)
                };
                Ok((change, 5))
            }
            SubscriptionOp::SubscribePattern => {
                if data.len() < 3 {
                    return Err(NegotiationError::TooShort {
                        expected: 3,
                        actual: data.len(),
                    });
                }
                let len = u16::from_le_bytes([data[1], data[2]]) as usize;
                if data.len() < 3 + len {
                    return Err(NegotiationError::TooShort {
                        expected: 3 + len,
                        actual: data.len(),
                    });
                }
                let pattern = String::from_utf8(data[3..3 + len].to_vec())
                    .map_err(|_| NegotiationError::InvalidData)?;
                Ok((Self::SubscribePattern(pattern), 3 + len))
            }
            SubscriptionOp::ClearAll => Ok((Self::ClearAll, 1)),
        }
    }
}

/// Tracks active subscriptions for a client
#[derive(Debug, Clone, Default)]
pub struct SubscriptionState {
    /// Subscribed region IDs
    regions: HashSet<u32>,
    /// Subscribed patterns (if supported)
    patterns: Vec<String>,
    /// Maximum allowed regions
    max_regions: u16,
}

impl SubscriptionState {
    /// Create new subscription state with limit
    pub fn new(max_regions: u16) -> Self {
        Self {
            regions: HashSet::new(),
            patterns: Vec::new(),
            max_regions,
        }
    }

    /// Apply a subscription change
    ///
    /// Returns true if the change was applied, false if rejected (e.g., at limit)
    pub fn apply(&mut self, change: &SubscriptionChange) -> bool {
        match change {
            SubscriptionChange::Subscribe(id) => {
                if self.regions.len() >= self.max_regions as usize {
                    return false;
                }
                self.regions.insert(*id);
                true
            }
            SubscriptionChange::Unsubscribe(id) => {
                self.regions.remove(id);
                true
            }
            SubscriptionChange::SubscribePattern(pattern) => {
                if self.patterns.len() >= self.max_regions as usize {
                    return false;
                }
                if !self.patterns.contains(pattern) {
                    self.patterns.push(pattern.clone());
                }
                true
            }
            SubscriptionChange::ClearAll => {
                self.regions.clear();
                self.patterns.clear();
                true
            }
        }
    }

    /// Check if a region ID is subscribed
    pub fn is_subscribed(&self, region_id: u32) -> bool {
        self.regions.contains(&region_id)
    }

    /// Check if a region matches any pattern
    ///
    /// This is a stub - real implementation would use proper pattern matching
    pub fn matches_pattern(&self, region_path: &str) -> bool {
        for pattern in &self.patterns {
            if pattern_matches(pattern, region_path) {
                return true;
            }
        }
        false
    }

    /// Get count of active subscriptions
    pub fn count(&self) -> usize {
        self.regions.len() + self.patterns.len()
    }

    /// Check if any subscriptions are active
    pub fn is_empty(&self) -> bool {
        self.regions.is_empty() && self.patterns.is_empty()
    }

    /// Get all subscribed region IDs
    pub fn region_ids(&self) -> impl Iterator<Item = &u32> {
        self.regions.iter()
    }

    /// Get all patterns
    pub fn patterns(&self) -> &[String] {
        &self.patterns
    }
}

/// Simple glob-style pattern matching
///
/// Supports:
/// - `*` matches any sequence within a segment
/// - `**` matches any sequence including path separators
fn pattern_matches(pattern: &str, path: &str) -> bool {
    // Handle exact match
    if pattern == path {
        return true;
    }

    // Handle ** (match everything)
    if pattern == "**" {
        return true;
    }

    // Handle trailing /*
    if let Some(prefix) = pattern.strip_suffix("/*") {
        if let Some(path_prefix) = path.rsplit_once('/') {
            return path_prefix.0 == prefix;
        }
        return false;
    }

    // Handle trailing /**
    if let Some(prefix) = pattern.strip_suffix("/**") {
        return path.starts_with(prefix) && path.len() > prefix.len();
    }

    // Handle prefix*
    if let Some(prefix) = pattern.strip_suffix('*') {
        return path.starts_with(prefix);
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_default() {
        let config = SelectiveSyncConfig::default();
        assert!(config.supports_regions());
        assert!(!config.supports_patterns());
        assert!(!config.supports_nested());
    }

    #[test]
    fn test_config_full() {
        let config = SelectiveSyncConfig::full();
        assert!(config.supports_regions());
        assert!(config.supports_patterns());
        assert!(config.supports_nested());
    }

    #[test]
    fn test_config_extension_roundtrip() {
        let config = SelectiveSyncConfig {
            flags: selective_sync_flags::REGION_OPS | selective_sync_flags::PATTERNS,
            max_regions: 512,
            max_expression_len: 200,
        };

        let ext = config.to_extension();
        let decoded = SelectiveSyncConfig::from_extension(&ext).unwrap();
        assert_eq!(decoded, config);
    }

    #[test]
    fn test_subscribe_roundtrip() {
        let change = SubscriptionChange::Subscribe(12345);
        let encoded = change.encode();
        let (decoded, len) = SubscriptionChange::decode(&encoded).unwrap();
        assert_eq!(decoded, change);
        assert_eq!(len, 5);
    }

    #[test]
    fn test_unsubscribe_roundtrip() {
        let change = SubscriptionChange::Unsubscribe(99999);
        let encoded = change.encode();
        let (decoded, _) = SubscriptionChange::decode(&encoded).unwrap();
        assert_eq!(decoded, change);
    }

    #[test]
    fn test_pattern_roundtrip() {
        let change = SubscriptionChange::SubscribePattern("users/*/profile".to_string());
        let encoded = change.encode();
        let (decoded, len) = SubscriptionChange::decode(&encoded).unwrap();
        assert_eq!(decoded, change);
        assert_eq!(len, 3 + 15); // op + len + "users/*/profile"
    }

    #[test]
    fn test_clear_all() {
        let change = SubscriptionChange::ClearAll;
        let encoded = change.encode();
        assert_eq!(encoded.len(), 1);
        let (decoded, len) = SubscriptionChange::decode(&encoded).unwrap();
        assert_eq!(decoded, change);
        assert_eq!(len, 1);
    }

    #[test]
    fn test_subscription_state() {
        let mut state = SubscriptionState::new(10);

        assert!(state.apply(&SubscriptionChange::Subscribe(1)));
        assert!(state.apply(&SubscriptionChange::Subscribe(2)));
        assert!(state.is_subscribed(1));
        assert!(state.is_subscribed(2));
        assert!(!state.is_subscribed(3));

        assert!(state.apply(&SubscriptionChange::Unsubscribe(1)));
        assert!(!state.is_subscribed(1));

        assert!(state.apply(&SubscriptionChange::ClearAll));
        assert!(state.is_empty());
    }

    #[test]
    fn test_subscription_limit() {
        let mut state = SubscriptionState::new(2);

        assert!(state.apply(&SubscriptionChange::Subscribe(1)));
        assert!(state.apply(&SubscriptionChange::Subscribe(2)));
        assert!(!state.apply(&SubscriptionChange::Subscribe(3))); // At limit

        assert_eq!(state.count(), 2);
    }

    #[test]
    fn test_pattern_matching() {
        assert!(pattern_matches("users/*", "users/alice"));
        assert!(!pattern_matches("users/*", "users/alice/profile"));
        assert!(pattern_matches("users/**", "users/alice/profile"));
        assert!(pattern_matches("data*", "database"));
        assert!(pattern_matches("**", "anything/at/all"));
        assert!(pattern_matches("exact", "exact"));
        assert!(!pattern_matches("exact", "not-exact"));
    }

    #[test]
    fn test_decode_invalid() {
        // Invalid op
        assert!(matches!(
            SubscriptionChange::decode(&[0xFF]),
            Err(NegotiationError::InvalidData)
        ));

        // Truncated subscribe
        assert!(matches!(
            SubscriptionChange::decode(&[0x00, 1, 2]),
            Err(NegotiationError::TooShort { .. })
        ));
    }
}
