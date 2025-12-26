//! Rate Hints extension (0x0004)
//!
//! Allows the server to hint acceptable update frequencies to clients,
//! enabling adaptive rate limiting without hard rejections.
//!
//! Wire format for extension negotiation:
//! ```text
//! +0  Flags (1 byte)
//!     - bit 0: Dynamic hints supported (server may send hints mid-session)
//!     - bit 1: Per-region hints supported
//! +1  Initial target rate (2 bytes LE16) - updates per second * 10
//! +3  Initial burst allowance (2 bytes LE16) - maximum burst size
//! ```
//!
//! Wire format for dynamic hint (sent in-band):
//! ```text
//! +0  Hint type (1 byte)
//!     - 0x00: Global rate hint
//!     - 0x01: Region-specific hint (followed by region ID)
//! +1  Target rate (2 bytes LE16) - updates per second * 10
//! +3  Burst allowance (2 bytes LE16)
//! +5  Duration hint (2 bytes LE16) - suggested duration in seconds (0 = indefinite)
//! +7  [Optional] Region ID (4 bytes LE32) - only if hint type is 0x01
//! ```

use super::negotiation::{ext_type, Extension, NegotiationError};
use std::time::Duration;

/// Rate hint flags
pub mod rate_hint_flags {
    /// Server may send dynamic rate hints during the session
    pub const DYNAMIC_HINTS: u8 = 0x01;
    /// Server may send per-region rate hints
    pub const PER_REGION_HINTS: u8 = 0x02;
}

/// Rate hints configuration for negotiation
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RateHintsConfig {
    /// Feature flags
    pub flags: u8,
    /// Initial target rate (updates per second * 10, so 1.5/s = 15)
    pub target_rate_x10: u16,
    /// Initial burst allowance
    pub burst_allowance: u16,
}

impl Default for RateHintsConfig {
    fn default() -> Self {
        Self {
            flags: rate_hint_flags::DYNAMIC_HINTS,
            target_rate_x10: 100, // 10 updates/second
            burst_allowance: 20,
        }
    }
}

impl RateHintsConfig {
    /// Create config with specific rate
    pub fn with_rate(updates_per_second: f32) -> Self {
        Self {
            flags: rate_hint_flags::DYNAMIC_HINTS,
            target_rate_x10: (updates_per_second * 10.0) as u16,
            burst_allowance: (updates_per_second * 2.0) as u16,
        }
    }

    /// Get target rate as updates per second
    pub fn target_rate(&self) -> f32 {
        self.target_rate_x10 as f32 / 10.0
    }

    /// Check if dynamic hints are supported
    pub fn supports_dynamic(&self) -> bool {
        (self.flags & rate_hint_flags::DYNAMIC_HINTS) != 0
    }

    /// Check if per-region hints are supported
    pub fn supports_per_region(&self) -> bool {
        (self.flags & rate_hint_flags::PER_REGION_HINTS) != 0
    }

    /// Wire size of config
    pub const fn wire_size() -> usize {
        5 // flags (1) + target_rate (2) + burst (2)
    }

    /// Encode to extension
    pub fn to_extension(&self) -> Extension {
        let mut data = Vec::with_capacity(Self::wire_size());
        data.push(self.flags);
        data.extend_from_slice(&self.target_rate_x10.to_le_bytes());
        data.extend_from_slice(&self.burst_allowance.to_le_bytes());
        Extension::new(ext_type::RATE_HINTS, data)
    }

    /// Decode from extension
    pub fn from_extension(ext: &Extension) -> Option<Self> {
        if ext.ext_type != ext_type::RATE_HINTS || ext.data.len() < Self::wire_size() {
            return None;
        }
        Some(Self {
            flags: ext.data[0],
            target_rate_x10: u16::from_le_bytes([ext.data[1], ext.data[2]]),
            burst_allowance: u16::from_le_bytes([ext.data[3], ext.data[4]]),
        })
    }

    /// Negotiate between client and server configs
    pub fn negotiate(client: &Self, server: &Self) -> Self {
        Self {
            // Only enable features both sides support
            flags: client.flags & server.flags,
            // Use the more restrictive rate
            target_rate_x10: client.target_rate_x10.min(server.target_rate_x10),
            burst_allowance: client.burst_allowance.min(server.burst_allowance),
        }
    }
}

/// Type of rate hint
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RateHintType {
    /// Global rate hint affecting all updates
    Global = 0x00,
    /// Region-specific rate hint
    Region = 0x01,
}

impl RateHintType {
    /// Convert from byte
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x00 => Some(Self::Global),
            0x01 => Some(Self::Region),
            _ => None,
        }
    }
}

/// A dynamic rate hint sent during the session
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RateHint {
    /// Type of hint
    pub hint_type: RateHintType,
    /// Target rate (updates per second * 10)
    pub target_rate_x10: u16,
    /// Burst allowance
    pub burst_allowance: u16,
    /// Suggested duration (0 = indefinite)
    pub duration_secs: u16,
    /// Region ID (only for Region type hints)
    pub region_id: Option<u32>,
}

impl RateHint {
    /// Create a global rate hint
    pub fn global(rate: f32, burst: u16, duration: Duration) -> Self {
        Self {
            hint_type: RateHintType::Global,
            target_rate_x10: (rate * 10.0) as u16,
            burst_allowance: burst,
            duration_secs: duration.as_secs().min(u16::MAX as u64) as u16,
            region_id: None,
        }
    }

    /// Create a region-specific rate hint
    pub fn region(region_id: u32, rate: f32, burst: u16, duration: Duration) -> Self {
        Self {
            hint_type: RateHintType::Region,
            target_rate_x10: (rate * 10.0) as u16,
            burst_allowance: burst,
            duration_secs: duration.as_secs().min(u16::MAX as u64) as u16,
            region_id: Some(region_id),
        }
    }

    /// Get target rate as updates per second
    pub fn target_rate(&self) -> f32 {
        self.target_rate_x10 as f32 / 10.0
    }

    /// Get duration (None if indefinite)
    pub fn duration(&self) -> Option<Duration> {
        if self.duration_secs == 0 {
            None
        } else {
            Some(Duration::from_secs(self.duration_secs as u64))
        }
    }

    /// Wire size
    pub fn wire_size(&self) -> usize {
        match self.hint_type {
            RateHintType::Global => 7,  // type(1) + rate(2) + burst(2) + duration(2)
            RateHintType::Region => 11, // + region_id(4)
        }
    }

    /// Encode to bytes
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(self.wire_size());
        buf.push(self.hint_type as u8);
        buf.extend_from_slice(&self.target_rate_x10.to_le_bytes());
        buf.extend_from_slice(&self.burst_allowance.to_le_bytes());
        buf.extend_from_slice(&self.duration_secs.to_le_bytes());

        if let Some(region_id) = self.region_id {
            buf.extend_from_slice(&region_id.to_le_bytes());
        }

        buf
    }

    /// Decode from bytes
    pub fn decode(data: &[u8]) -> Result<Self, NegotiationError> {
        if data.len() < 7 {
            return Err(NegotiationError::TooShort {
                expected: 7,
                actual: data.len(),
            });
        }

        let hint_type = RateHintType::from_byte(data[0]).ok_or(NegotiationError::InvalidData)?;
        let target_rate_x10 = u16::from_le_bytes([data[1], data[2]]);
        let burst_allowance = u16::from_le_bytes([data[3], data[4]]);
        let duration_secs = u16::from_le_bytes([data[5], data[6]]);

        let region_id = if hint_type == RateHintType::Region {
            if data.len() < 11 {
                return Err(NegotiationError::TooShort {
                    expected: 11,
                    actual: data.len(),
                });
            }
            Some(u32::from_le_bytes([data[7], data[8], data[9], data[10]]))
        } else {
            None
        };

        Ok(Self {
            hint_type,
            target_rate_x10,
            burst_allowance,
            duration_secs,
            region_id,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_default() {
        let config = RateHintsConfig::default();
        assert_eq!(config.target_rate(), 10.0);
        assert!(config.supports_dynamic());
        assert!(!config.supports_per_region());
    }

    #[test]
    fn test_config_with_rate() {
        let config = RateHintsConfig::with_rate(5.5);
        assert_eq!(config.target_rate_x10, 55);
        assert_eq!(config.target_rate(), 5.5);
    }

    #[test]
    fn test_config_extension_roundtrip() {
        let config = RateHintsConfig {
            flags: rate_hint_flags::DYNAMIC_HINTS | rate_hint_flags::PER_REGION_HINTS,
            target_rate_x10: 150,
            burst_allowance: 30,
        };

        let ext = config.to_extension();
        let decoded = RateHintsConfig::from_extension(&ext).unwrap();
        assert_eq!(decoded, config);
    }

    #[test]
    fn test_config_negotiate() {
        let client = RateHintsConfig {
            flags: rate_hint_flags::DYNAMIC_HINTS | rate_hint_flags::PER_REGION_HINTS,
            target_rate_x10: 200,
            burst_allowance: 50,
        };
        let server = RateHintsConfig {
            flags: rate_hint_flags::DYNAMIC_HINTS, // No per-region
            target_rate_x10: 100,
            burst_allowance: 20,
        };

        let result = RateHintsConfig::negotiate(&client, &server);
        assert!(result.supports_dynamic());
        assert!(!result.supports_per_region()); // Not supported by server
        assert_eq!(result.target_rate_x10, 100);
        assert_eq!(result.burst_allowance, 20);
    }

    #[test]
    fn test_global_hint_roundtrip() {
        let hint = RateHint::global(5.0, 10, Duration::from_secs(60));

        let encoded = hint.encode();
        assert_eq!(encoded.len(), 7);

        let decoded = RateHint::decode(&encoded).unwrap();
        assert_eq!(decoded.hint_type, RateHintType::Global);
        assert_eq!(decoded.target_rate(), 5.0);
        assert_eq!(decoded.burst_allowance, 10);
        assert_eq!(decoded.duration(), Some(Duration::from_secs(60)));
        assert!(decoded.region_id.is_none());
    }

    #[test]
    fn test_region_hint_roundtrip() {
        let hint = RateHint::region(42, 2.5, 5, Duration::from_secs(120));

        let encoded = hint.encode();
        assert_eq!(encoded.len(), 11);

        let decoded = RateHint::decode(&encoded).unwrap();
        assert_eq!(decoded.hint_type, RateHintType::Region);
        assert_eq!(decoded.target_rate(), 2.5);
        assert_eq!(decoded.region_id, Some(42));
    }

    #[test]
    fn test_indefinite_duration() {
        let hint = RateHint::global(10.0, 20, Duration::ZERO);
        assert_eq!(hint.duration_secs, 0);
        assert!(hint.duration().is_none());
    }

    #[test]
    fn test_decode_truncated() {
        assert!(matches!(
            RateHint::decode(&[0, 1, 2, 3, 4, 5]),
            Err(NegotiationError::TooShort { .. })
        ));

        // Region hint without region ID
        assert!(matches!(
            RateHint::decode(&[0x01, 1, 2, 3, 4, 5, 6]),
            Err(NegotiationError::TooShort { .. })
        ));
    }

    #[test]
    fn test_invalid_hint_type() {
        let data = [0xFF, 1, 2, 3, 4, 5, 6];
        assert!(matches!(
            RateHint::decode(&data),
            Err(NegotiationError::InvalidData)
        ));
    }
}
