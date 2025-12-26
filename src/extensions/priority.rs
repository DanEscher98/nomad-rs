//! Priority extension (0x0002)
//!
//! Allows marking updates with priority levels so that critical state changes
//! (e.g., error conditions, user input acknowledgment) can be prioritized over
//! cosmetic updates (e.g., progress bars, animations).
//!
//! Wire format for extension data:
//! ```text
//! +0  Supported levels bitmap (1 byte)
//!     - bit 0: CRITICAL supported
//!     - bit 1: HIGH supported
//!     - bit 2: NORMAL supported
//!     - bit 3: LOW supported
//!     - bit 4: BACKGROUND supported
//! +1  Default priority (1 byte, 0-4)
//! ```
//!
//! When attached to a sync message, priority is encoded as a single byte (0-4).

use super::negotiation::{ext_type, Extension};

/// Priority levels for state updates
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
#[repr(u8)]
pub enum Priority {
    /// Must be delivered immediately, may preempt other updates
    /// Use for: error states, disconnect notices, critical alerts
    Critical = 0,

    /// Important updates that should be delivered promptly
    /// Use for: user input acknowledgment, command responses
    High = 1,

    /// Standard priority for most updates
    /// Use for: regular state synchronization
    #[default]
    Normal = 2,

    /// Can be delayed if bandwidth is constrained
    /// Use for: progress updates, non-critical status
    Low = 3,

    /// Lowest priority, deliver when convenient
    /// Use for: analytics, telemetry, prefetch
    Background = 4,
}

impl Priority {
    /// Convert from wire format byte
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0 => Some(Priority::Critical),
            1 => Some(Priority::High),
            2 => Some(Priority::Normal),
            3 => Some(Priority::Low),
            4 => Some(Priority::Background),
            _ => None,
        }
    }

    /// Convert to wire format byte
    pub fn to_byte(self) -> u8 {
        self as u8
    }

    /// Get bitmask for this priority level
    pub fn to_bitmask(self) -> u8 {
        1 << (self as u8)
    }
}

/// Bitmap of supported priority levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PrioritySupportBitmap(pub u8);

impl PrioritySupportBitmap {
    /// All priority levels supported
    pub const ALL: Self = Self(0b00011111);

    /// Only normal priority (minimal support)
    pub const NORMAL_ONLY: Self = Self(0b00000100);

    /// Check if a priority level is supported
    pub fn supports(&self, priority: Priority) -> bool {
        (self.0 & priority.to_bitmask()) != 0
    }

    /// Add support for a priority level
    pub fn add(&mut self, priority: Priority) {
        self.0 |= priority.to_bitmask();
    }

    /// Remove support for a priority level
    pub fn remove(&mut self, priority: Priority) {
        self.0 &= !priority.to_bitmask();
    }

    /// Iterate over supported priorities (highest to lowest)
    pub fn iter_supported(&self) -> impl Iterator<Item = Priority> + '_ {
        [
            Priority::Critical,
            Priority::High,
            Priority::Normal,
            Priority::Low,
            Priority::Background,
        ]
        .into_iter()
        .filter(|p| self.supports(*p))
    }
}

/// Priority extension configuration
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PriorityConfig {
    /// Bitmap of supported priority levels
    pub supported: PrioritySupportBitmap,
    /// Default priority for messages without explicit priority
    pub default: Priority,
}

impl Default for PriorityConfig {
    fn default() -> Self {
        Self {
            supported: PrioritySupportBitmap::ALL,
            default: Priority::Normal,
        }
    }
}

impl PriorityConfig {
    /// Create config supporting all priorities
    pub fn all() -> Self {
        Self::default()
    }

    /// Create config with only normal priority
    pub fn minimal() -> Self {
        Self {
            supported: PrioritySupportBitmap::NORMAL_ONLY,
            default: Priority::Normal,
        }
    }

    /// Wire size of this config
    pub const fn wire_size() -> usize {
        2 // supported bitmap (1) + default (1)
    }

    /// Encode to extension
    pub fn to_extension(&self) -> Extension {
        Extension::new(ext_type::PRIORITY, vec![self.supported.0, self.default.to_byte()])
    }

    /// Decode from extension
    pub fn from_extension(ext: &Extension) -> Option<Self> {
        if ext.ext_type != ext_type::PRIORITY || ext.data.len() < 2 {
            return None;
        }
        let default = Priority::from_byte(ext.data[1])?;
        Some(Self {
            supported: PrioritySupportBitmap(ext.data[0]),
            default,
        })
    }

    /// Negotiate between client and server configs
    ///
    /// Returns the intersection of supported levels with the lower default priority.
    pub fn negotiate(client: &Self, server: &Self) -> Self {
        let supported = PrioritySupportBitmap(client.supported.0 & server.supported.0);
        let default = client.default.max(server.default); // Higher value = lower priority
        Self { supported, default }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_priority_ordering() {
        assert!(Priority::Critical < Priority::High);
        assert!(Priority::High < Priority::Normal);
        assert!(Priority::Normal < Priority::Low);
        assert!(Priority::Low < Priority::Background);
    }

    #[test]
    fn test_priority_byte_roundtrip() {
        for p in [
            Priority::Critical,
            Priority::High,
            Priority::Normal,
            Priority::Low,
            Priority::Background,
        ] {
            assert_eq!(Priority::from_byte(p.to_byte()), Some(p));
        }
        assert_eq!(Priority::from_byte(5), None);
        assert_eq!(Priority::from_byte(255), None);
    }

    #[test]
    fn test_bitmap_operations() {
        let mut bitmap = PrioritySupportBitmap(0);
        assert!(!bitmap.supports(Priority::Normal));

        bitmap.add(Priority::Normal);
        bitmap.add(Priority::High);
        assert!(bitmap.supports(Priority::Normal));
        assert!(bitmap.supports(Priority::High));
        assert!(!bitmap.supports(Priority::Critical));

        bitmap.remove(Priority::Normal);
        assert!(!bitmap.supports(Priority::Normal));
        assert!(bitmap.supports(Priority::High));
    }

    #[test]
    fn test_bitmap_all() {
        let bitmap = PrioritySupportBitmap::ALL;
        assert!(bitmap.supports(Priority::Critical));
        assert!(bitmap.supports(Priority::High));
        assert!(bitmap.supports(Priority::Normal));
        assert!(bitmap.supports(Priority::Low));
        assert!(bitmap.supports(Priority::Background));
    }

    #[test]
    fn test_config_extension_roundtrip() {
        let config = PriorityConfig {
            supported: PrioritySupportBitmap::ALL,
            default: Priority::Low,
        };

        let ext = config.to_extension();
        assert_eq!(ext.ext_type, ext_type::PRIORITY);

        let decoded = PriorityConfig::from_extension(&ext).unwrap();
        assert_eq!(decoded, config);
    }

    #[test]
    fn test_negotiate() {
        let client = PriorityConfig {
            supported: PrioritySupportBitmap(0b00011111), // All
            default: Priority::Normal,
        };
        let server = PriorityConfig {
            supported: PrioritySupportBitmap(0b00000111), // Critical, High, Normal only
            default: Priority::High,
        };

        let result = PriorityConfig::negotiate(&client, &server);

        // Intersection of supported levels
        assert!(result.supported.supports(Priority::Critical));
        assert!(result.supported.supports(Priority::High));
        assert!(result.supported.supports(Priority::Normal));
        assert!(!result.supported.supports(Priority::Low));
        assert!(!result.supported.supports(Priority::Background));

        // Default is the higher value (lower priority) between Normal and High
        assert_eq!(result.default, Priority::Normal);
    }
}
