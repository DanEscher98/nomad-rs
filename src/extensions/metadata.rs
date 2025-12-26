//! Metadata extension (0x0007)
//!
//! Allows attaching contextual metadata to sync updates, including:
//! - Timestamps (for ordering, latency measurement)
//! - User/session identifiers (for multi-user scenarios)
//! - Causality information (vector clocks, happens-before)
//! - Custom application-defined metadata
//!
//! Wire format for extension negotiation:
//! ```text
//! +0  Flags (1 byte)
//!     - bit 0: Timestamps supported
//!     - bit 1: User IDs supported
//!     - bit 2: Causality tracking supported
//!     - bit 3: Custom metadata supported
//! +1  Max custom metadata size (2 bytes LE16)
//! +3  Max causality entries (1 byte) - for vector clocks
//! ```
//!
//! Wire format for metadata block (attached to sync messages):
//! ```text
//! +0  Present flags (1 byte) - which fields are present
//! +1  [Optional] Timestamp (8 bytes LE64) - microseconds since epoch
//! +N  [Optional] User ID length (1 byte) + User ID bytes
//! +M  [Optional] Causality entry count (1 byte) + entries
//!     - Each entry: User ID length (1) + User ID + Counter (8 bytes LE64)
//! +K  [Optional] Custom length (2 bytes LE16) + Custom data
//! ```

use super::negotiation::{ext_type, Extension, NegotiationError};
use std::collections::BTreeMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Metadata configuration flags
pub mod metadata_config_flags {
    /// Timestamps can be attached
    pub const TIMESTAMPS: u8 = 0x01;
    /// User/session IDs can be attached
    pub const USER_IDS: u8 = 0x02;
    /// Causality tracking (vector clocks)
    pub const CAUSALITY: u8 = 0x04;
    /// Custom application metadata
    pub const CUSTOM: u8 = 0x08;
}

/// Metadata presence flags (in wire format)
pub mod metadata_presence_flags {
    /// Timestamp is present
    pub const TIMESTAMP: u8 = 0x01;
    /// User ID is present
    pub const USER_ID: u8 = 0x02;
    /// Causality info is present
    pub const CAUSALITY: u8 = 0x04;
    /// Custom data is present
    pub const CUSTOM: u8 = 0x08;
}

/// Metadata configuration
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetadataConfig {
    /// Feature flags
    pub flags: u8,
    /// Maximum custom metadata size
    pub max_custom_size: u16,
    /// Maximum causality entries (vector clock size)
    pub max_causality_entries: u8,
}

impl Default for MetadataConfig {
    fn default() -> Self {
        Self {
            flags: metadata_config_flags::TIMESTAMPS | metadata_config_flags::USER_IDS,
            max_custom_size: 256,
            max_causality_entries: 16,
        }
    }
}

impl MetadataConfig {
    /// Create config with all features
    pub fn full() -> Self {
        Self {
            flags: metadata_config_flags::TIMESTAMPS
                | metadata_config_flags::USER_IDS
                | metadata_config_flags::CAUSALITY
                | metadata_config_flags::CUSTOM,
            max_custom_size: 1024,
            max_causality_entries: 32,
        }
    }

    /// Create minimal config (timestamps only)
    pub fn minimal() -> Self {
        Self {
            flags: metadata_config_flags::TIMESTAMPS,
            max_custom_size: 0,
            max_causality_entries: 0,
        }
    }

    /// Check if timestamps are supported
    pub fn supports_timestamps(&self) -> bool {
        (self.flags & metadata_config_flags::TIMESTAMPS) != 0
    }

    /// Check if user IDs are supported
    pub fn supports_user_ids(&self) -> bool {
        (self.flags & metadata_config_flags::USER_IDS) != 0
    }

    /// Check if causality tracking is supported
    pub fn supports_causality(&self) -> bool {
        (self.flags & metadata_config_flags::CAUSALITY) != 0
    }

    /// Check if custom metadata is supported
    pub fn supports_custom(&self) -> bool {
        (self.flags & metadata_config_flags::CUSTOM) != 0
    }

    /// Wire size
    pub const fn wire_size() -> usize {
        4 // flags(1) + max_custom(2) + max_causality(1)
    }

    /// Encode to extension
    pub fn to_extension(&self) -> Extension {
        let mut data = Vec::with_capacity(Self::wire_size());
        data.push(self.flags);
        data.extend_from_slice(&self.max_custom_size.to_le_bytes());
        data.push(self.max_causality_entries);
        Extension::new(ext_type::METADATA, data)
    }

    /// Decode from extension
    pub fn from_extension(ext: &Extension) -> Option<Self> {
        if ext.ext_type != ext_type::METADATA || ext.data.len() < Self::wire_size() {
            return None;
        }
        Some(Self {
            flags: ext.data[0],
            max_custom_size: u16::from_le_bytes([ext.data[1], ext.data[2]]),
            max_causality_entries: ext.data[3],
        })
    }

    /// Negotiate between client and server
    pub fn negotiate(client: &Self, server: &Self) -> Self {
        Self {
            flags: client.flags & server.flags,
            max_custom_size: client.max_custom_size.min(server.max_custom_size),
            max_causality_entries: client.max_causality_entries.min(server.max_causality_entries),
        }
    }
}

/// A vector clock for causality tracking
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct VectorClock {
    /// Mapping of participant ID to logical timestamp
    entries: BTreeMap<String, u64>,
}

impl VectorClock {
    /// Create empty vector clock
    pub fn new() -> Self {
        Self::default()
    }

    /// Increment counter for a participant
    pub fn increment(&mut self, participant: &str) {
        let counter = self.entries.entry(participant.to_string()).or_insert(0);
        *counter += 1;
    }

    /// Get counter for a participant
    pub fn get(&self, participant: &str) -> u64 {
        self.entries.get(participant).copied().unwrap_or(0)
    }

    /// Set counter for a participant
    pub fn set(&mut self, participant: String, counter: u64) {
        self.entries.insert(participant, counter);
    }

    /// Merge with another vector clock (take max of each entry)
    pub fn merge(&mut self, other: &VectorClock) {
        for (id, &counter) in &other.entries {
            let entry = self.entries.entry(id.clone()).or_insert(0);
            *entry = (*entry).max(counter);
        }
    }

    /// Check if this clock happens-before another
    pub fn happens_before(&self, other: &VectorClock) -> bool {
        let mut dominated = false;

        // Check all entries in self are <= other
        for (id, &counter) in &self.entries {
            let other_counter = other.get(id);
            if counter > other_counter {
                return false;
            }
            if counter < other_counter {
                dominated = true;
            }
        }

        // Check if other has any entries not in self
        for (id, &counter) in &other.entries {
            if !self.entries.contains_key(id) && counter > 0 {
                dominated = true;
            }
        }

        dominated
    }

    /// Check if two clocks are concurrent (neither happens-before the other)
    pub fn is_concurrent_with(&self, other: &VectorClock) -> bool {
        !self.happens_before(other) && !other.happens_before(self)
    }

    /// Number of entries
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Iterate over entries
    pub fn iter(&self) -> impl Iterator<Item = (&String, &u64)> {
        self.entries.iter()
    }

    /// Encode to bytes
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.push(self.entries.len() as u8);

        for (id, counter) in &self.entries {
            buf.push(id.len() as u8);
            buf.extend_from_slice(id.as_bytes());
            buf.extend_from_slice(&counter.to_le_bytes());
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

        let count = data[0] as usize;
        let mut offset = 1;
        let mut clock = Self::new();

        for _ in 0..count {
            if offset >= data.len() {
                return Err(NegotiationError::TooShort {
                    expected: offset + 1,
                    actual: data.len(),
                });
            }

            let id_len = data[offset] as usize;
            offset += 1;

            if offset + id_len + 8 > data.len() {
                return Err(NegotiationError::TooShort {
                    expected: offset + id_len + 8,
                    actual: data.len(),
                });
            }

            let id = String::from_utf8(data[offset..offset + id_len].to_vec())
                .map_err(|_| NegotiationError::InvalidData)?;
            offset += id_len;

            let counter = u64::from_le_bytes(
                data[offset..offset + 8]
                    .try_into()
                    .expect("length checked"),
            );
            offset += 8;

            clock.set(id, counter);
        }

        Ok((clock, offset))
    }
}

/// Metadata attached to a sync message
#[derive(Debug, Clone, Default)]
pub struct Metadata {
    /// Timestamp (microseconds since epoch)
    pub timestamp: Option<u64>,
    /// User/session identifier
    pub user_id: Option<String>,
    /// Causality information
    pub causality: Option<VectorClock>,
    /// Custom application data
    pub custom: Option<Vec<u8>>,
}

impl Metadata {
    /// Create empty metadata
    pub fn new() -> Self {
        Self::default()
    }

    /// Create with current timestamp
    pub fn with_timestamp() -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_micros() as u64;
        Self {
            timestamp: Some(timestamp),
            ..Default::default()
        }
    }

    /// Set timestamp from SystemTime
    pub fn set_timestamp(&mut self, time: SystemTime) {
        self.timestamp = Some(
            time.duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_micros() as u64,
        );
    }

    /// Get timestamp as SystemTime
    pub fn get_timestamp(&self) -> Option<SystemTime> {
        self.timestamp.map(|micros| {
            UNIX_EPOCH + Duration::from_micros(micros)
        })
    }

    /// Set user ID
    pub fn set_user_id(&mut self, user_id: impl Into<String>) {
        self.user_id = Some(user_id.into());
    }

    /// Set causality
    pub fn set_causality(&mut self, clock: VectorClock) {
        self.causality = Some(clock);
    }

    /// Set custom data
    pub fn set_custom(&mut self, data: Vec<u8>) {
        self.custom = Some(data);
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.timestamp.is_none()
            && self.user_id.is_none()
            && self.causality.is_none()
            && self.custom.is_none()
    }

    /// Compute presence flags
    fn presence_flags(&self) -> u8 {
        let mut flags = 0u8;
        if self.timestamp.is_some() {
            flags |= metadata_presence_flags::TIMESTAMP;
        }
        if self.user_id.is_some() {
            flags |= metadata_presence_flags::USER_ID;
        }
        if self.causality.is_some() {
            flags |= metadata_presence_flags::CAUSALITY;
        }
        if self.custom.is_some() {
            flags |= metadata_presence_flags::CUSTOM;
        }
        flags
    }

    /// Encode to bytes
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.push(self.presence_flags());

        if let Some(ts) = self.timestamp {
            buf.extend_from_slice(&ts.to_le_bytes());
        }

        if let Some(ref user_id) = self.user_id {
            buf.push(user_id.len() as u8);
            buf.extend_from_slice(user_id.as_bytes());
        }

        if let Some(ref causality) = self.causality {
            buf.extend_from_slice(&causality.encode());
        }

        if let Some(ref custom) = self.custom {
            buf.extend_from_slice(&(custom.len() as u16).to_le_bytes());
            buf.extend_from_slice(custom);
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

        let flags = data[0];
        let mut offset = 1;
        let mut metadata = Self::new();

        if (flags & metadata_presence_flags::TIMESTAMP) != 0 {
            if offset + 8 > data.len() {
                return Err(NegotiationError::TooShort {
                    expected: offset + 8,
                    actual: data.len(),
                });
            }
            metadata.timestamp = Some(u64::from_le_bytes(
                data[offset..offset + 8]
                    .try_into()
                    .expect("length checked"),
            ));
            offset += 8;
        }

        if (flags & metadata_presence_flags::USER_ID) != 0 {
            if offset >= data.len() {
                return Err(NegotiationError::TooShort {
                    expected: offset + 1,
                    actual: data.len(),
                });
            }
            let id_len = data[offset] as usize;
            offset += 1;

            if offset + id_len > data.len() {
                return Err(NegotiationError::TooShort {
                    expected: offset + id_len,
                    actual: data.len(),
                });
            }
            metadata.user_id = Some(
                String::from_utf8(data[offset..offset + id_len].to_vec())
                    .map_err(|_| NegotiationError::InvalidData)?,
            );
            offset += id_len;
        }

        if (flags & metadata_presence_flags::CAUSALITY) != 0 {
            let (clock, consumed) = VectorClock::decode(&data[offset..])?;
            metadata.causality = Some(clock);
            offset += consumed;
        }

        if (flags & metadata_presence_flags::CUSTOM) != 0 {
            if offset + 2 > data.len() {
                return Err(NegotiationError::TooShort {
                    expected: offset + 2,
                    actual: data.len(),
                });
            }
            let custom_len = u16::from_le_bytes([data[offset], data[offset + 1]]) as usize;
            offset += 2;

            if offset + custom_len > data.len() {
                return Err(NegotiationError::TooShort {
                    expected: offset + custom_len,
                    actual: data.len(),
                });
            }
            metadata.custom = Some(data[offset..offset + custom_len].to_vec());
            offset += custom_len;
        }

        Ok((metadata, offset))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_default() {
        let config = MetadataConfig::default();
        assert!(config.supports_timestamps());
        assert!(config.supports_user_ids());
        assert!(!config.supports_causality());
        assert!(!config.supports_custom());
    }

    #[test]
    fn test_config_extension_roundtrip() {
        let config = MetadataConfig::full();
        let ext = config.to_extension();
        let decoded = MetadataConfig::from_extension(&ext).unwrap();
        assert_eq!(decoded, config);
    }

    #[test]
    fn test_config_negotiate() {
        let client = MetadataConfig::full();
        let server = MetadataConfig::minimal();

        let result = MetadataConfig::negotiate(&client, &server);
        assert!(result.supports_timestamps());
        assert!(!result.supports_user_ids());
        assert!(!result.supports_causality());
        assert!(!result.supports_custom());
    }

    #[test]
    fn test_vector_clock_increment() {
        let mut clock = VectorClock::new();
        clock.increment("alice");
        clock.increment("alice");
        clock.increment("bob");

        assert_eq!(clock.get("alice"), 2);
        assert_eq!(clock.get("bob"), 1);
        assert_eq!(clock.get("charlie"), 0);
    }

    #[test]
    fn test_vector_clock_merge() {
        let mut clock1 = VectorClock::new();
        clock1.set("alice".to_string(), 3);
        clock1.set("bob".to_string(), 1);

        let mut clock2 = VectorClock::new();
        clock2.set("alice".to_string(), 1);
        clock2.set("bob".to_string(), 5);
        clock2.set("charlie".to_string(), 2);

        clock1.merge(&clock2);

        assert_eq!(clock1.get("alice"), 3); // max(3, 1)
        assert_eq!(clock1.get("bob"), 5); // max(1, 5)
        assert_eq!(clock1.get("charlie"), 2); // new entry
    }

    #[test]
    fn test_vector_clock_happens_before() {
        let mut clock1 = VectorClock::new();
        clock1.set("alice".to_string(), 1);
        clock1.set("bob".to_string(), 2);

        let mut clock2 = VectorClock::new();
        clock2.set("alice".to_string(), 2);
        clock2.set("bob".to_string(), 3);

        assert!(clock1.happens_before(&clock2));
        assert!(!clock2.happens_before(&clock1));
    }

    #[test]
    fn test_vector_clock_concurrent() {
        let mut clock1 = VectorClock::new();
        clock1.set("alice".to_string(), 2);
        clock1.set("bob".to_string(), 1);

        let mut clock2 = VectorClock::new();
        clock2.set("alice".to_string(), 1);
        clock2.set("bob".to_string(), 2);

        assert!(clock1.is_concurrent_with(&clock2));
    }

    #[test]
    fn test_vector_clock_roundtrip() {
        let mut clock = VectorClock::new();
        clock.set("user1".to_string(), 10);
        clock.set("user2".to_string(), 20);

        let encoded = clock.encode();
        let (decoded, _) = VectorClock::decode(&encoded).unwrap();

        assert_eq!(decoded.get("user1"), 10);
        assert_eq!(decoded.get("user2"), 20);
    }

    #[test]
    fn test_metadata_empty() {
        let metadata = Metadata::new();
        assert!(metadata.is_empty());

        let encoded = metadata.encode();
        assert_eq!(encoded.len(), 1); // Just flags byte
        assert_eq!(encoded[0], 0);
    }

    #[test]
    fn test_metadata_timestamp_only() {
        let mut metadata = Metadata::new();
        metadata.timestamp = Some(1234567890);

        let encoded = metadata.encode();
        let (decoded, _) = Metadata::decode(&encoded).unwrap();

        assert_eq!(decoded.timestamp, Some(1234567890));
        assert!(decoded.user_id.is_none());
    }

    #[test]
    fn test_metadata_full_roundtrip() {
        let mut clock = VectorClock::new();
        clock.set("alice".to_string(), 5);

        let mut metadata = Metadata::new();
        metadata.timestamp = Some(9999999);
        metadata.user_id = Some("test-user".to_string());
        metadata.causality = Some(clock);
        metadata.custom = Some(vec![0xDE, 0xAD, 0xBE, 0xEF]);

        let encoded = metadata.encode();
        let (decoded, _) = Metadata::decode(&encoded).unwrap();

        assert_eq!(decoded.timestamp, Some(9999999));
        assert_eq!(decoded.user_id, Some("test-user".to_string()));
        assert!(decoded.causality.is_some());
        assert_eq!(decoded.causality.as_ref().unwrap().get("alice"), 5);
        assert_eq!(decoded.custom, Some(vec![0xDE, 0xAD, 0xBE, 0xEF]));
    }

    #[test]
    fn test_metadata_with_timestamp() {
        let metadata = Metadata::with_timestamp();
        assert!(metadata.timestamp.is_some());
        assert!(metadata.timestamp.unwrap() > 0);
    }

    #[test]
    fn test_decode_truncated() {
        // Timestamp flag set but no data
        assert!(matches!(
            Metadata::decode(&[metadata_presence_flags::TIMESTAMP]),
            Err(NegotiationError::TooShort { .. })
        ));

        // User ID flag set but no length
        assert!(matches!(
            Metadata::decode(&[metadata_presence_flags::USER_ID]),
            Err(NegotiationError::TooShort { .. })
        ));
    }
}
