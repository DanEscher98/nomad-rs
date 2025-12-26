//! Batching extension (0x0003)
//!
//! Allows combining multiple small state updates into a single frame to reduce
//! overhead and improve throughput for high-frequency update scenarios.
//!
//! Wire format for extension negotiation:
//! ```text
//! +0  Max batch size (2 bytes LE16) - maximum updates per batch
//! +2  Max batch bytes (2 bytes LE16) - maximum total payload size
//! +4  Max delay ms (2 bytes LE16) - maximum time to hold updates for batching
//! ```
//!
//! Wire format for batched payload:
//! ```text
//! +0  Update count (2 bytes LE16)
//! +2  For each update:
//!     +0  Update length (2 bytes LE16)
//!     +2  Update data (variable)
//! ```

use super::negotiation::{ext_type, Extension, NegotiationError};
use std::time::Duration;

/// Default maximum updates per batch
pub const DEFAULT_MAX_BATCH_SIZE: u16 = 32;

/// Default maximum batch payload size (16 KB)
pub const DEFAULT_MAX_BATCH_BYTES: u16 = 16384;

/// Default maximum delay before flushing batch (50ms)
pub const DEFAULT_MAX_DELAY_MS: u16 = 50;

/// Batching extension configuration
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchingConfig {
    /// Maximum number of updates per batch
    pub max_batch_size: u16,
    /// Maximum total payload bytes per batch
    pub max_batch_bytes: u16,
    /// Maximum time to hold updates for batching
    pub max_delay_ms: u16,
}

impl Default for BatchingConfig {
    fn default() -> Self {
        Self {
            max_batch_size: DEFAULT_MAX_BATCH_SIZE,
            max_batch_bytes: DEFAULT_MAX_BATCH_BYTES,
            max_delay_ms: DEFAULT_MAX_DELAY_MS,
        }
    }
}

impl BatchingConfig {
    /// Create config optimized for low latency (smaller batches, shorter delays)
    pub fn low_latency() -> Self {
        Self {
            max_batch_size: 8,
            max_batch_bytes: 4096,
            max_delay_ms: 10,
        }
    }

    /// Create config optimized for high throughput (larger batches, longer delays)
    pub fn high_throughput() -> Self {
        Self {
            max_batch_size: 128,
            max_batch_bytes: 65535,
            max_delay_ms: 100,
        }
    }

    /// Get max delay as Duration
    pub fn max_delay(&self) -> Duration {
        Duration::from_millis(self.max_delay_ms as u64)
    }

    /// Wire size of this config
    pub const fn wire_size() -> usize {
        6 // max_size (2) + max_bytes (2) + max_delay (2)
    }

    /// Encode to extension
    pub fn to_extension(&self) -> Extension {
        let mut data = Vec::with_capacity(Self::wire_size());
        data.extend_from_slice(&self.max_batch_size.to_le_bytes());
        data.extend_from_slice(&self.max_batch_bytes.to_le_bytes());
        data.extend_from_slice(&self.max_delay_ms.to_le_bytes());
        Extension::new(ext_type::BATCHING, data)
    }

    /// Decode from extension
    pub fn from_extension(ext: &Extension) -> Option<Self> {
        if ext.ext_type != ext_type::BATCHING || ext.data.len() < Self::wire_size() {
            return None;
        }
        Some(Self {
            max_batch_size: u16::from_le_bytes([ext.data[0], ext.data[1]]),
            max_batch_bytes: u16::from_le_bytes([ext.data[2], ext.data[3]]),
            max_delay_ms: u16::from_le_bytes([ext.data[4], ext.data[5]]),
        })
    }

    /// Negotiate between client and server configs
    ///
    /// Takes the minimum of each parameter.
    pub fn negotiate(client: &Self, server: &Self) -> Self {
        Self {
            max_batch_size: client.max_batch_size.min(server.max_batch_size),
            max_batch_bytes: client.max_batch_bytes.min(server.max_batch_bytes),
            max_delay_ms: client.max_delay_ms.min(server.max_delay_ms),
        }
    }
}

/// A batch of updates ready for transmission
#[derive(Debug, Clone)]
pub struct Batch {
    updates: Vec<Vec<u8>>,
    total_bytes: usize,
}

impl Default for Batch {
    fn default() -> Self {
        Self::new()
    }
}

impl Batch {
    /// Create a new empty batch
    pub fn new() -> Self {
        Self {
            updates: Vec::new(),
            total_bytes: 0,
        }
    }

    /// Create batch with capacity hint
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            updates: Vec::with_capacity(capacity),
            total_bytes: 0,
        }
    }

    /// Number of updates in the batch
    pub fn len(&self) -> usize {
        self.updates.len()
    }

    /// Check if batch is empty
    pub fn is_empty(&self) -> bool {
        self.updates.is_empty()
    }

    /// Total payload bytes (excluding headers)
    pub fn total_bytes(&self) -> usize {
        self.total_bytes
    }

    /// Add an update to the batch
    ///
    /// Returns false if the update doesn't fit (caller should flush first).
    pub fn try_add(&mut self, update: Vec<u8>, config: &BatchingConfig) -> bool {
        let new_size = self.updates.len() + 1;
        let new_bytes = self.total_bytes + update.len() + 2; // +2 for length prefix

        if new_size > config.max_batch_size as usize
            || new_bytes > config.max_batch_bytes as usize
        {
            return false;
        }

        self.total_bytes += update.len() + 2;
        self.updates.push(update);
        true
    }

    /// Encode batch to wire format
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(2 + self.total_bytes);
        buf.extend_from_slice(&(self.updates.len() as u16).to_le_bytes());

        for update in &self.updates {
            buf.extend_from_slice(&(update.len() as u16).to_le_bytes());
            buf.extend_from_slice(update);
        }

        buf
    }

    /// Decode batch from wire format
    pub fn decode(data: &[u8]) -> Result<Self, NegotiationError> {
        if data.len() < 2 {
            return Err(NegotiationError::TooShort {
                expected: 2,
                actual: data.len(),
            });
        }

        let count = u16::from_le_bytes([data[0], data[1]]) as usize;
        let mut offset = 2;
        let mut updates = Vec::with_capacity(count);
        let mut total_bytes = 0;

        for _ in 0..count {
            if offset + 2 > data.len() {
                return Err(NegotiationError::TooShort {
                    expected: offset + 2,
                    actual: data.len(),
                });
            }

            let len = u16::from_le_bytes([data[offset], data[offset + 1]]) as usize;
            offset += 2;

            if offset + len > data.len() {
                return Err(NegotiationError::TooShort {
                    expected: offset + len,
                    actual: data.len(),
                });
            }

            updates.push(data[offset..offset + len].to_vec());
            total_bytes += len + 2;
            offset += len;
        }

        Ok(Self {
            updates,
            total_bytes,
        })
    }

    /// Consume batch and return updates
    pub fn into_updates(self) -> Vec<Vec<u8>> {
        self.updates
    }

    /// Iterate over updates
    pub fn iter(&self) -> impl Iterator<Item = &[u8]> {
        self.updates.iter().map(|v| v.as_slice())
    }

    /// Clear the batch
    pub fn clear(&mut self) {
        self.updates.clear();
        self.total_bytes = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_default() {
        let config = BatchingConfig::default();
        assert_eq!(config.max_batch_size, DEFAULT_MAX_BATCH_SIZE);
        assert_eq!(config.max_batch_bytes, DEFAULT_MAX_BATCH_BYTES);
        assert_eq!(config.max_delay_ms, DEFAULT_MAX_DELAY_MS);
    }

    #[test]
    fn test_config_extension_roundtrip() {
        let config = BatchingConfig {
            max_batch_size: 100,
            max_batch_bytes: 8192,
            max_delay_ms: 25,
        };

        let ext = config.to_extension();
        assert_eq!(ext.ext_type, ext_type::BATCHING);

        let decoded = BatchingConfig::from_extension(&ext).unwrap();
        assert_eq!(decoded, config);
    }

    #[test]
    fn test_config_negotiate() {
        let client = BatchingConfig {
            max_batch_size: 64,
            max_batch_bytes: 32768,
            max_delay_ms: 100,
        };
        let server = BatchingConfig {
            max_batch_size: 32,
            max_batch_bytes: 16384,
            max_delay_ms: 50,
        };

        let result = BatchingConfig::negotiate(&client, &server);
        assert_eq!(result.max_batch_size, 32);
        assert_eq!(result.max_batch_bytes, 16384);
        assert_eq!(result.max_delay_ms, 50);
    }

    #[test]
    fn test_batch_add_and_encode() {
        let config = BatchingConfig::default();
        let mut batch = Batch::new();

        assert!(batch.try_add(vec![1, 2, 3], &config));
        assert!(batch.try_add(vec![4, 5], &config));
        assert_eq!(batch.len(), 2);

        let encoded = batch.encode();
        let decoded = Batch::decode(&encoded).unwrap();

        assert_eq!(decoded.len(), 2);
        let updates: Vec<_> = decoded.iter().collect();
        assert_eq!(updates[0], &[1, 2, 3]);
        assert_eq!(updates[1], &[4, 5]);
    }

    #[test]
    fn test_batch_size_limit() {
        let config = BatchingConfig {
            max_batch_size: 2,
            max_batch_bytes: 1000,
            max_delay_ms: 50,
        };
        let mut batch = Batch::new();

        assert!(batch.try_add(vec![1], &config));
        assert!(batch.try_add(vec![2], &config));
        assert!(!batch.try_add(vec![3], &config)); // Should fail
        assert_eq!(batch.len(), 2);
    }

    #[test]
    fn test_batch_bytes_limit() {
        let config = BatchingConfig {
            max_batch_size: 100,
            max_batch_bytes: 10, // Very small
            max_delay_ms: 50,
        };
        let mut batch = Batch::new();

        assert!(batch.try_add(vec![1, 2, 3], &config)); // 3 + 2 = 5 bytes
        assert!(!batch.try_add(vec![1, 2, 3, 4, 5, 6], &config)); // Would exceed 10
        assert_eq!(batch.len(), 1);
    }

    #[test]
    fn test_batch_empty() {
        let batch = Batch::new();
        assert!(batch.is_empty());
        assert_eq!(batch.len(), 0);

        let encoded = batch.encode();
        let decoded = Batch::decode(&encoded).unwrap();
        assert!(decoded.is_empty());
    }

    #[test]
    fn test_batch_decode_truncated() {
        // Too short for header
        assert!(matches!(
            Batch::decode(&[0]),
            Err(NegotiationError::TooShort { .. })
        ));

        // Claims 1 update but no data
        assert!(matches!(
            Batch::decode(&[1, 0]),
            Err(NegotiationError::TooShort { .. })
        ));

        // Claims 1 update with length 5 but only 2 bytes of data
        assert!(matches!(
            Batch::decode(&[1, 0, 5, 0, 1, 2]),
            Err(NegotiationError::TooShort { .. })
        ));
    }

    #[test]
    fn test_presets() {
        let low_lat = BatchingConfig::low_latency();
        let high_tp = BatchingConfig::high_throughput();

        assert!(low_lat.max_batch_size < high_tp.max_batch_size);
        assert!(low_lat.max_delay_ms < high_tp.max_delay_ms);
    }
}
