//! Extension negotiation
//!
//! Implements TLV-based extension negotiation during handshake.
//! See 4-EXTENSIONS.md for specification.

use thiserror::Error;

/// Extension type identifiers
pub mod ext_type {
    /// Compression extension (zstd)
    pub const COMPRESSION: u16 = 0x0001;
    /// Scrollback extension (terminal-specific)
    pub const SCROLLBACK: u16 = 0x0002;
    /// Prediction extension (terminal-specific)
    pub const PREDICTION: u16 = 0x0003;
}

/// Errors from extension negotiation.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum NegotiationError {
    /// Input buffer is too short to contain valid extension data.
    #[error("buffer too short: expected {expected}, got {actual}")]
    TooShort {
        /// Minimum bytes required.
        expected: usize,
        /// Actual bytes available.
        actual: usize,
    },

    /// Extension data is malformed or invalid.
    #[error("invalid extension data")]
    InvalidData,

    /// Requested extension type is not supported by this implementation.
    #[error("extension not supported: 0x{0:04x}")]
    NotSupported(u16),

    /// Output buffer is too small to hold encoded extension.
    #[error("buffer too small for encoding")]
    BufferTooSmall,
}

/// Extension TLV (Type-Length-Value) format
///
/// Wire format:
/// ```text
/// +0   Extension Type (2 bytes LE16)
/// +2   Extension Length (2 bytes LE16)
/// +4   Extension Data (variable)
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Extension {
    /// Extension type identifier
    pub ext_type: u16,
    /// Extension data
    pub data: Vec<u8>,
}

/// Header size for extension TLV
pub const EXTENSION_HEADER_SIZE: usize = 4;

impl Extension {
    /// Create a new extension
    pub fn new(ext_type: u16, data: Vec<u8>) -> Self {
        Self { ext_type, data }
    }

    /// Create an empty extension (no data)
    pub fn empty(ext_type: u16) -> Self {
        Self {
            ext_type,
            data: Vec::new(),
        }
    }

    /// Create compression extension with level
    pub fn compression(level: u8) -> Self {
        Self {
            ext_type: ext_type::COMPRESSION,
            data: vec![level],
        }
    }

    /// Get compression level if this is a compression extension
    pub fn compression_level(&self) -> Option<u8> {
        if self.ext_type == ext_type::COMPRESSION && !self.data.is_empty() {
            Some(self.data[0])
        } else {
            None
        }
    }

    /// Total wire size
    pub fn wire_size(&self) -> usize {
        EXTENSION_HEADER_SIZE + self.data.len()
    }

    /// Encode to bytes
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(self.wire_size());
        buf.extend_from_slice(&self.ext_type.to_le_bytes());
        buf.extend_from_slice(&(self.data.len() as u16).to_le_bytes());
        buf.extend_from_slice(&self.data);
        buf
    }

    /// Encode into buffer, returns bytes written
    pub fn encode_into(&self, buf: &mut [u8]) -> Result<usize, NegotiationError> {
        let size = self.wire_size();
        if buf.len() < size {
            return Err(NegotiationError::BufferTooSmall);
        }

        buf[0..2].copy_from_slice(&self.ext_type.to_le_bytes());
        buf[2..4].copy_from_slice(&(self.data.len() as u16).to_le_bytes());
        buf[4..size].copy_from_slice(&self.data);

        Ok(size)
    }

    /// Decode from bytes
    pub fn decode(data: &[u8]) -> Result<Self, NegotiationError> {
        if data.len() < EXTENSION_HEADER_SIZE {
            return Err(NegotiationError::TooShort {
                expected: EXTENSION_HEADER_SIZE,
                actual: data.len(),
            });
        }

        let ext_type =
            u16::from_le_bytes(data[0..2].try_into().expect("length checked above"));
        let ext_len =
            u16::from_le_bytes(data[2..4].try_into().expect("length checked above")) as usize;

        if data.len() < EXTENSION_HEADER_SIZE + ext_len {
            return Err(NegotiationError::TooShort {
                expected: EXTENSION_HEADER_SIZE + ext_len,
                actual: data.len(),
            });
        }

        let ext_data = data[EXTENSION_HEADER_SIZE..EXTENSION_HEADER_SIZE + ext_len].to_vec();

        Ok(Self {
            ext_type,
            data: ext_data,
        })
    }

    /// Decode from bytes, returning extension and bytes consumed
    pub fn decode_with_length(data: &[u8]) -> Result<(Self, usize), NegotiationError> {
        let ext = Self::decode(data)?;
        let consumed = ext.wire_size();
        Ok((ext, consumed))
    }
}

/// Extension set for negotiation
#[derive(Debug, Clone, Default)]
pub struct ExtensionSet {
    extensions: Vec<Extension>,
}

impl ExtensionSet {
    /// Create an empty extension set
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an extension
    pub fn add(&mut self, ext: Extension) {
        // Replace if already exists
        if let Some(existing) = self.extensions.iter_mut().find(|e| e.ext_type == ext.ext_type) {
            *existing = ext;
        } else {
            self.extensions.push(ext);
        }
    }

    /// Add compression extension
    pub fn add_compression(&mut self, level: u8) {
        self.add(Extension::compression(level));
    }

    /// Get extension by type
    pub fn get(&self, ext_type: u16) -> Option<&Extension> {
        self.extensions.iter().find(|e| e.ext_type == ext_type)
    }

    /// Check if extension is present
    pub fn has(&self, ext_type: u16) -> bool {
        self.extensions.iter().any(|e| e.ext_type == ext_type)
    }

    /// Check if compression is enabled
    pub fn has_compression(&self) -> bool {
        self.has(ext_type::COMPRESSION)
    }

    /// Get compression level if enabled
    pub fn compression_level(&self) -> Option<u8> {
        self.get(ext_type::COMPRESSION)
            .and_then(|e| e.compression_level())
    }

    /// Get all extensions
    pub fn iter(&self) -> impl Iterator<Item = &Extension> {
        self.extensions.iter()
    }

    /// Number of extensions
    pub fn len(&self) -> usize {
        self.extensions.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.extensions.is_empty()
    }

    /// Total wire size
    pub fn wire_size(&self) -> usize {
        self.extensions.iter().map(|e| e.wire_size()).sum()
    }

    /// Encode all extensions
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(self.wire_size());
        for ext in &self.extensions {
            buf.extend_from_slice(&ext.encode());
        }
        buf
    }

    /// Decode all extensions from buffer
    pub fn decode(mut data: &[u8]) -> Result<Self, NegotiationError> {
        let mut set = Self::new();

        while !data.is_empty() {
            let (ext, consumed) = Extension::decode_with_length(data)?;
            set.add(ext);
            data = &data[consumed..];
        }

        Ok(set)
    }

    /// Remove an extension by type
    pub fn remove(&mut self, ext_type: u16) -> Option<Extension> {
        if let Some(pos) = self.extensions.iter().position(|e| e.ext_type == ext_type) {
            Some(self.extensions.remove(pos))
        } else {
            None
        }
    }

    /// Clear all extensions
    pub fn clear(&mut self) {
        self.extensions.clear();
    }
}

/// Negotiate extensions between client and server offers
///
/// Returns the intersection of supported extensions.
pub fn negotiate(offered: &ExtensionSet, supported: &ExtensionSet) -> ExtensionSet {
    let mut result = ExtensionSet::new();

    for ext in offered.iter() {
        if let Some(supported_ext) = supported.get(ext.ext_type) {
            // For compression, use the lower level
            if ext.ext_type == ext_type::COMPRESSION {
                let offered_level = ext.compression_level().unwrap_or(3);
                let supported_level = supported_ext.compression_level().unwrap_or(3);
                result.add(Extension::compression(offered_level.min(supported_level)));
            } else {
                // For other extensions, use the offered version
                result.add(ext.clone());
            }
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extension_encode_decode() {
        let ext = Extension::new(0x1234, vec![1, 2, 3, 4]);

        let encoded = ext.encode();
        assert_eq!(encoded.len(), EXTENSION_HEADER_SIZE + 4);

        let decoded = Extension::decode(&encoded).unwrap();
        assert_eq!(decoded, ext);
    }

    #[test]
    fn test_compression_extension() {
        let ext = Extension::compression(5);

        assert_eq!(ext.ext_type, ext_type::COMPRESSION);
        assert_eq!(ext.compression_level(), Some(5));

        // Roundtrip
        let encoded = ext.encode();
        let decoded = Extension::decode(&encoded).unwrap();
        assert_eq!(decoded.compression_level(), Some(5));
    }

    #[test]
    fn test_empty_extension() {
        let ext = Extension::empty(0xFFFF);

        assert_eq!(ext.wire_size(), EXTENSION_HEADER_SIZE);
        assert!(ext.data.is_empty());

        let encoded = ext.encode();
        let decoded = Extension::decode(&encoded).unwrap();
        assert_eq!(decoded, ext);
    }

    #[test]
    fn test_decode_too_short() {
        let data = [0u8; 2];
        let result = Extension::decode(&data);
        assert!(matches!(result, Err(NegotiationError::TooShort { .. })));
    }

    #[test]
    fn test_decode_data_truncated() {
        // Header says 10 bytes of data, but only 2 provided
        let data = [0x01, 0x00, 0x0A, 0x00, 0x01, 0x02];
        let result = Extension::decode(&data);
        assert!(matches!(result, Err(NegotiationError::TooShort { .. })));
    }

    #[test]
    fn test_extension_set() {
        let mut set = ExtensionSet::new();

        set.add_compression(5);
        set.add(Extension::empty(0x1234));

        assert_eq!(set.len(), 2);
        assert!(set.has_compression());
        assert!(set.has(0x1234));
        assert!(!set.has(0x9999));

        assert_eq!(set.compression_level(), Some(5));
    }

    #[test]
    fn test_extension_set_encode_decode() {
        let mut set = ExtensionSet::new();
        set.add_compression(3);
        set.add(Extension::new(0x0100, vec![0xAA, 0xBB]));

        let encoded = set.encode();
        let decoded = ExtensionSet::decode(&encoded).unwrap();

        assert_eq!(decoded.len(), 2);
        assert_eq!(decoded.compression_level(), Some(3));
        assert!(decoded.has(0x0100));
    }

    #[test]
    fn test_extension_set_replace() {
        let mut set = ExtensionSet::new();

        set.add_compression(3);
        assert_eq!(set.compression_level(), Some(3));

        set.add_compression(10);
        assert_eq!(set.compression_level(), Some(10));
        assert_eq!(set.len(), 1); // Still only one compression ext
    }

    #[test]
    fn test_negotiate_extensions() {
        let mut client = ExtensionSet::new();
        client.add_compression(10);
        client.add(Extension::empty(0x1234));

        let mut server = ExtensionSet::new();
        server.add_compression(5);
        // Server doesn't support 0x1234

        let result = negotiate(&client, &server);

        assert_eq!(result.len(), 1);
        assert!(result.has_compression());
        assert_eq!(result.compression_level(), Some(5)); // Lower of 10 and 5
        assert!(!result.has(0x1234)); // Not supported by server
    }

    #[test]
    fn test_negotiate_no_overlap() {
        let mut client = ExtensionSet::new();
        client.add(Extension::empty(0x1111));

        let mut server = ExtensionSet::new();
        server.add(Extension::empty(0x2222));

        let result = negotiate(&client, &server);
        assert!(result.is_empty());
    }

    #[test]
    fn test_extension_set_remove() {
        let mut set = ExtensionSet::new();
        set.add_compression(5);
        set.add(Extension::empty(0x1234));

        assert_eq!(set.len(), 2);

        let removed = set.remove(ext_type::COMPRESSION);
        assert!(removed.is_some());
        assert_eq!(set.len(), 1);
        assert!(!set.has_compression());
    }

    #[test]
    fn test_encode_into() {
        let ext = Extension::new(0x1234, vec![1, 2, 3]);
        let mut buf = [0u8; 100];

        let written = ext.encode_into(&mut buf).unwrap();
        assert_eq!(written, EXTENSION_HEADER_SIZE + 3);

        let decoded = Extension::decode(&buf[..written]).unwrap();
        assert_eq!(decoded, ext);
    }

    #[test]
    fn test_encode_into_too_small() {
        let ext = Extension::new(0x1234, vec![1, 2, 3, 4, 5]);
        let mut buf = [0u8; 4]; // Too small

        let result = ext.encode_into(&mut buf);
        assert!(matches!(result, Err(NegotiationError::BufferTooSmall)));
    }
}
