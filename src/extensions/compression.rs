//! Compression extension
//!
//! Implements zstd compression for sync message payloads.
//! See 4-EXTENSIONS.md for specification.

use thiserror::Error;

/// Minimum payload size to attempt compression
pub const MIN_COMPRESS_SIZE: usize = 64;

/// Default zstd compression level (1-22, higher = smaller but slower)
pub const DEFAULT_COMPRESSION_LEVEL: i32 = 3;

/// Errors from compression operations.
#[derive(Debug, Error)]
pub enum CompressionError {
    /// Zstd compression failed.
    #[error("compression failed: {0}")]
    CompressionFailed(String),

    /// Zstd decompression failed.
    #[error("decompression failed: {0}")]
    DecompressionFailed(String),

    /// Compressed data is malformed or corrupted.
    #[error("invalid compressed data")]
    InvalidData,

    /// Decompressed size exceeds safety limit (DoS protection).
    #[error("decompressed size exceeded limit: {size} > {limit}")]
    SizeExceeded {
        /// Actual decompressed size.
        size: usize,
        /// Maximum allowed size.
        limit: usize,
    },
}

/// Compression configuration
#[derive(Debug, Clone)]
pub struct CompressionConfig {
    /// Minimum size to attempt compression
    pub min_size: usize,
    /// Compression level (1-22)
    pub level: i32,
    /// Maximum decompressed size (for DoS protection)
    pub max_decompressed_size: usize,
}

impl Default for CompressionConfig {
    fn default() -> Self {
        Self {
            min_size: MIN_COMPRESS_SIZE,
            level: DEFAULT_COMPRESSION_LEVEL,
            max_decompressed_size: 1024 * 1024, // 1 MB default limit
        }
    }
}

/// Compressor for sync payloads
#[derive(Debug, Clone)]
pub struct Compressor {
    config: CompressionConfig,
}

impl Compressor {
    /// Create a new compressor with default settings
    pub fn new() -> Self {
        Self {
            config: CompressionConfig::default(),
        }
    }

    /// Create a compressor with custom config
    pub fn with_config(config: CompressionConfig) -> Self {
        Self { config }
    }

    /// Set compression level
    pub fn set_level(&mut self, level: i32) {
        self.config.level = level.clamp(1, 22);
    }

    /// Get compression level
    pub fn level(&self) -> i32 {
        self.config.level
    }

    /// Compress data if it meets the minimum size threshold
    ///
    /// Returns the original data if compression isn't beneficial.
    pub fn compress(&self, data: &[u8]) -> Result<CompressResult, CompressionError> {
        // Skip compression for small payloads
        if data.len() < self.config.min_size {
            return Ok(CompressResult::Uncompressed(data.to_vec()));
        }

        // Compress
        let compressed = zstd::encode_all(data, self.config.level)
            .map_err(|e| CompressionError::CompressionFailed(e.to_string()))?;

        // Only use compression if it actually saves space
        if compressed.len() >= data.len() {
            return Ok(CompressResult::Uncompressed(data.to_vec()));
        }

        Ok(CompressResult::Compressed(compressed))
    }

    /// Compress data in-place into a buffer
    ///
    /// Returns the number of bytes written and whether compression was used.
    pub fn compress_into(
        &self,
        data: &[u8],
        buf: &mut [u8],
    ) -> Result<(usize, bool), CompressionError> {
        if data.len() < self.config.min_size {
            if buf.len() < data.len() {
                return Err(CompressionError::CompressionFailed(
                    "buffer too small".to_string(),
                ));
            }
            buf[..data.len()].copy_from_slice(data);
            return Ok((data.len(), false));
        }

        // Compress to temporary buffer first
        let compressed = zstd::encode_all(data, self.config.level)
            .map_err(|e| CompressionError::CompressionFailed(e.to_string()))?;

        if compressed.len() >= data.len() {
            // Compression didn't help
            if buf.len() < data.len() {
                return Err(CompressionError::CompressionFailed(
                    "buffer too small".to_string(),
                ));
            }
            buf[..data.len()].copy_from_slice(data);
            Ok((data.len(), false))
        } else {
            if buf.len() < compressed.len() {
                return Err(CompressionError::CompressionFailed(
                    "buffer too small".to_string(),
                ));
            }
            buf[..compressed.len()].copy_from_slice(&compressed);
            Ok((compressed.len(), true))
        }
    }

    /// Decompress data
    pub fn decompress(&self, data: &[u8]) -> Result<Vec<u8>, CompressionError> {
        // Create a decoder with size limit
        let mut decoder = zstd::Decoder::new(data)
            .map_err(|e| CompressionError::DecompressionFailed(e.to_string()))?;

        let mut output = Vec::new();
        std::io::Read::read_to_end(&mut decoder, &mut output)
            .map_err(|e| CompressionError::DecompressionFailed(e.to_string()))?;

        if output.len() > self.config.max_decompressed_size {
            return Err(CompressionError::SizeExceeded {
                size: output.len(),
                limit: self.config.max_decompressed_size,
            });
        }

        Ok(output)
    }

    /// Decompress data with explicit size limit
    pub fn decompress_with_limit(
        &self,
        data: &[u8],
        max_size: usize,
    ) -> Result<Vec<u8>, CompressionError> {
        let mut decoder = zstd::Decoder::new(data)
            .map_err(|e| CompressionError::DecompressionFailed(e.to_string()))?;

        let mut output = Vec::new();
        std::io::Read::read_to_end(&mut decoder, &mut output)
            .map_err(|e| CompressionError::DecompressionFailed(e.to_string()))?;

        if output.len() > max_size {
            return Err(CompressionError::SizeExceeded {
                size: output.len(),
                limit: max_size,
            });
        }

        Ok(output)
    }
}

impl Default for Compressor {
    fn default() -> Self {
        Self::new()
    }
}

/// Result of compression attempt
#[derive(Debug, Clone)]
pub enum CompressResult {
    /// Data was compressed
    Compressed(Vec<u8>),
    /// Data was not compressed (too small or compression not beneficial)
    Uncompressed(Vec<u8>),
}

impl CompressResult {
    /// Get the data bytes
    pub fn data(&self) -> &[u8] {
        match self {
            CompressResult::Compressed(data) => data,
            CompressResult::Uncompressed(data) => data,
        }
    }

    /// Check if data was compressed
    pub fn is_compressed(&self) -> bool {
        matches!(self, CompressResult::Compressed(_))
    }

    /// Consume and get the data
    pub fn into_data(self) -> Vec<u8> {
        match self {
            CompressResult::Compressed(data) => data,
            CompressResult::Uncompressed(data) => data,
        }
    }
}

/// Statistics for compression operations
#[derive(Debug, Clone, Default)]
pub struct CompressionStats {
    /// Total bytes before compression
    pub total_uncompressed: u64,
    /// Total bytes after compression
    pub total_compressed: u64,
    /// Number of payloads compressed
    pub compressed_count: u64,
    /// Number of payloads skipped (too small or no benefit)
    pub skipped_count: u64,
}

impl CompressionStats {
    /// Get compression ratio (compressed / uncompressed)
    pub fn ratio(&self) -> f64 {
        if self.total_uncompressed == 0 {
            1.0
        } else {
            self.total_compressed as f64 / self.total_uncompressed as f64
        }
    }

    /// Get bytes saved
    pub fn bytes_saved(&self) -> u64 {
        self.total_uncompressed.saturating_sub(self.total_compressed)
    }

    /// Record a compression result
    pub fn record(&mut self, original_size: usize, result: &CompressResult) {
        self.total_uncompressed += original_size as u64;
        match result {
            CompressResult::Compressed(data) => {
                self.total_compressed += data.len() as u64;
                self.compressed_count += 1;
            }
            CompressResult::Uncompressed(data) => {
                self.total_compressed += data.len() as u64;
                self.skipped_count += 1;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compress_small_data() {
        let compressor = Compressor::new();
        let data = b"hello";

        let result = compressor.compress(data).unwrap();
        assert!(!result.is_compressed());
        assert_eq!(result.data(), data);
    }

    #[test]
    fn test_compress_large_data() {
        let compressor = Compressor::new();
        // Create compressible data (repetitive)
        let data: Vec<u8> = (0..1000).map(|i| (i % 256) as u8).collect();

        let result = compressor.compress(&data).unwrap();
        // Should compress well since it's repetitive
        assert!(result.is_compressed());
        assert!(result.data().len() < data.len());
    }

    #[test]
    fn test_decompress() {
        let compressor = Compressor::new();
        let data: Vec<u8> = (0..1000).map(|i| (i % 256) as u8).collect();

        let result = compressor.compress(&data).unwrap();
        assert!(result.is_compressed());

        let decompressed = compressor.decompress(result.data()).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_roundtrip() {
        let compressor = Compressor::new();
        let data: Vec<u8> = (0..2000).map(|i| (i % 256) as u8).collect();

        let compressed = compressor.compress(&data).unwrap();
        let decompressed = if compressed.is_compressed() {
            compressor.decompress(compressed.data()).unwrap()
        } else {
            compressed.into_data()
        };

        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_incompressible_data() {
        let compressor = Compressor::new();
        // Random-ish data that doesn't compress well
        let data: Vec<u8> = (0..200).map(|i| ((i * 17 + 31) % 256) as u8).collect();

        let result = compressor.compress(&data).unwrap();
        // May or may not compress, but should always be valid
        if result.is_compressed() {
            let decompressed = compressor.decompress(result.data()).unwrap();
            assert_eq!(decompressed, data);
        } else {
            assert_eq!(result.data(), data.as_slice());
        }
    }

    #[test]
    fn test_size_limit() {
        let compressor = Compressor::with_config(CompressionConfig {
            max_decompressed_size: 100,
            ..Default::default()
        });

        // Compress some data larger than limit
        let data: Vec<u8> = vec![0; 200];
        let result = compressor.compress(&data).unwrap();

        // Decompression should fail due to size limit
        let err = compressor.decompress(result.data());
        assert!(matches!(err, Err(CompressionError::SizeExceeded { .. })));
    }

    #[test]
    fn test_compression_stats() {
        let compressor = Compressor::new();
        let mut stats = CompressionStats::default();

        // Small data (skipped)
        let small = b"hi";
        let result = compressor.compress(small).unwrap();
        stats.record(small.len(), &result);

        // Large data (compressed)
        let large: Vec<u8> = vec![0; 1000];
        let result = compressor.compress(&large).unwrap();
        stats.record(large.len(), &result);

        assert_eq!(stats.skipped_count, 1);
        assert_eq!(stats.compressed_count, 1);
        assert!(stats.bytes_saved() > 0);
    }

    #[test]
    fn test_compression_level() {
        let mut compressor = Compressor::new();
        assert_eq!(compressor.level(), DEFAULT_COMPRESSION_LEVEL);

        compressor.set_level(10);
        assert_eq!(compressor.level(), 10);

        // Should clamp to valid range
        compressor.set_level(100);
        assert_eq!(compressor.level(), 22);

        compressor.set_level(0);
        assert_eq!(compressor.level(), 1);
    }

    #[test]
    fn test_compress_into() {
        let compressor = Compressor::new();
        let data: Vec<u8> = vec![0; 1000];
        let mut buf = vec![0u8; 2000];

        let (written, compressed) = compressor.compress_into(&data, &mut buf).unwrap();
        assert!(compressed);
        assert!(written < data.len());

        // Verify we can decompress
        let decompressed = compressor.decompress(&buf[..written]).unwrap();
        assert_eq!(decompressed, data);
    }
}
