//! NOMAD Echo Example
//!
//! A simple echo state implementation for conformance testing.
//! Now with proper Noise_IK handshake and encrypted communication.
//!
//! # Environment Variables
//!
//! - `NOMAD_MODE`: "server" or "client" (required)
//! - `NOMAD_SERVER_PUBLIC_KEY`: Base64-encoded server public key (client needs this)
//! - `NOMAD_SERVER_HOST`: Server hostname (client only, default: 127.0.0.1)
//! - `NOMAD_SERVER_PORT`: Server port (both, default: 19999)
//! - `NOMAD_BIND_ADDR`: Bind address (server only, default: 0.0.0.0)
//! - `NOMAD_HEALTH_PORT`: Health check port (both, default: 8080)
//! - `NOMAD_PERSISTENT`: "true" for persistent client mode (client only)
//!
//! # Key Management
//!
//! When starting in server mode, the server generates a keypair and prints
//! the public key in base64 format. Copy this to the client's
//! NOMAD_SERVER_PUBLIC_KEY environment variable.
//!
//! # Examples
//!
//! Start the server (prints public key):
//! ```bash
//! NOMAD_MODE=server cargo run -p nomad-echo
//! ```
//!
//! Start the client with server's public key:
//! ```bash
//! NOMAD_MODE=client NOMAD_SERVER_PUBLIC_KEY=<base64-pubkey> cargo run -p nomad-echo
//! ```
//!
//! Persistent client mode (interactive):
//! ```bash
//! NOMAD_MODE=client NOMAD_PERSISTENT=true NOMAD_SERVER_PUBLIC_KEY=<key> cargo run -p nomad-echo
//! ```

mod client;
mod health;
mod server;
mod state;

use std::env;
use std::net::SocketAddr;

use client::{EchoClient, EchoClientConfig};
use health::{start_health_server, HealthState};
use nomad_protocol::crypto::StaticKeypair;
use server::{EchoServer, EchoServerConfig};

/// Parse a key from base64 (or return None if not set/invalid).
fn parse_key(env_var: &str) -> Option<[u8; 32]> {
    match env::var(env_var) {
        Ok(b64) => {
            let bytes = decode_base64(&b64).ok()?;
            if bytes.len() == 32 {
                let mut key = [0u8; 32];
                key.copy_from_slice(&bytes);
                Some(key)
            } else {
                eprintln!("Warning: {} has wrong length ({}), ignoring", env_var, bytes.len());
                None
            }
        }
        Err(_) => None,
    }
}

/// Encode bytes as base64.
fn encode_base64(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let mut output = String::with_capacity((data.len() + 2) / 3 * 4);

    for chunk in data.chunks(3) {
        let b0 = chunk[0] as usize;
        let b1 = chunk.get(1).copied().unwrap_or(0) as usize;
        let b2 = chunk.get(2).copied().unwrap_or(0) as usize;

        let combined = (b0 << 16) | (b1 << 8) | b2;

        output.push(ALPHABET[(combined >> 18) & 0x3F] as char);
        output.push(ALPHABET[(combined >> 12) & 0x3F] as char);

        if chunk.len() > 1 {
            output.push(ALPHABET[(combined >> 6) & 0x3F] as char);
        } else {
            output.push('=');
        }

        if chunk.len() > 2 {
            output.push(ALPHABET[combined & 0x3F] as char);
        } else {
            output.push('=');
        }
    }

    output
}

/// Simple base64 decode.
fn decode_base64(input: &str) -> Result<Vec<u8>, &'static str> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let input = input.trim().as_bytes();
    let mut output = Vec::with_capacity(input.len() * 3 / 4);

    let mut buffer = 0u32;
    let mut bits = 0u32;

    for &byte in input {
        if byte == b'=' {
            break;
        }

        let value = ALPHABET
            .iter()
            .position(|&c| c == byte)
            .ok_or("invalid base64")?
            as u32;

        buffer = (buffer << 6) | value;
        bits += 6;

        if bits >= 8 {
            bits -= 8;
            output.push((buffer >> bits) as u8);
            buffer &= (1 << bits) - 1;
        }
    }

    Ok(output)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mode = env::var("NOMAD_MODE").unwrap_or_else(|_| "server".to_string());
    let port: u16 = env::var("NOMAD_SERVER_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(19999);
    let health_port: u16 = env::var("NOMAD_HEALTH_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(8080);

    eprintln!("NOMAD Echo - mode: {}", mode);

    match mode.as_str() {
        "server" => run_server(port, health_port).await,
        "client" => run_client(port, health_port).await,
        _ => {
            eprintln!("Unknown mode: {}. Use 'server' or 'client'", mode);
            std::process::exit(1);
        }
    }
}

async fn run_server(
    port: u16,
    health_port: u16,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let bind_addr: SocketAddr = env::var("NOMAD_BIND_ADDR")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| format!("0.0.0.0:{}", port).parse().unwrap());

    // Check for test mode or pre-shared keypair
    let use_test_keys = env::var("NOMAD_TEST_MODE")
        .map(|v| v == "true" || v == "1")
        .unwrap_or(false);

    let keypair = if use_test_keys {
        // Well-known test keypair for conformance testing
        // Deterministic X25519 keypair - DO NOT USE IN PRODUCTION
        eprintln!("WARNING: Using test keypair (NOMAD_TEST_MODE=true)");

        // Test private key (arbitrary bytes - x25519 will clamp internally)
        let test_private: [u8; 32] = [
            0x48, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x7f,
        ];
        // Derive public key from private key using x25519
        let secret = x25519_dalek::StaticSecret::from(test_private);
        let public = x25519_dalek::PublicKey::from(&secret);
        let test_public = *public.as_bytes();
        eprintln!("Test public key (base64): {}", encode_base64(&test_public));
        StaticKeypair::from_bytes(test_private, test_public)
    } else if let Some(private_key) = parse_key("NOMAD_SERVER_PRIVATE_KEY") {
        if let Some(public_key) = parse_key("NOMAD_SERVER_PUBLIC_KEY") {
            eprintln!("Using provided server keypair from environment");
            StaticKeypair::from_bytes(private_key, public_key)
        } else {
            eprintln!("Warning: NOMAD_SERVER_PRIVATE_KEY set but no NOMAD_SERVER_PUBLIC_KEY");
            eprintln!("Generating new keypair instead");
            StaticKeypair::generate()
        }
    } else {
        StaticKeypair::generate()
    };

    let public_key_b64 = encode_base64(keypair.public_key());

    eprintln!("=== Server Public Key (for clients) ===");
    eprintln!("{}", public_key_b64);
    eprintln!("========================================");

    let config = EchoServerConfig::new(bind_addr, keypair);
    let server = EchoServer::new(config);
    let health_state = HealthState::server();

    // Start health server in background
    let health_addr: SocketAddr = format!("0.0.0.0:{}", health_port).parse()?;
    let health_state_clone = health_state.clone();
    tokio::spawn(async move {
        if let Err(e) = start_health_server(health_addr, health_state_clone).await {
            eprintln!("Health server error: {}", e);
        }
    });

    // Run echo server
    server.run().await
}

async fn run_client(
    port: u16,
    health_port: u16,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let server_host = env::var("NOMAD_SERVER_HOST").unwrap_or_else(|_| "127.0.0.1".to_string());

    // Resolve hostname to socket address (supports both IP and DNS names)
    let server_addr: SocketAddr = tokio::net::lookup_host(format!("{}:{}", server_host, port))
        .await?
        .next()
        .ok_or("Failed to resolve server address")?;

    // Get server public key
    let server_public_key = match parse_key("NOMAD_SERVER_PUBLIC_KEY") {
        Some(key) => {
            eprintln!("Using provided server public key");
            key
        }
        None => {
            eprintln!("Warning: No NOMAD_SERVER_PUBLIC_KEY provided.");
            eprintln!("Using zero key - handshake will fail unless server also uses zero key.");
            eprintln!("Set NOMAD_SERVER_PUBLIC_KEY to the base64 key printed by the server.");
            [0u8; 32]
        }
    };

    let persistent = env::var("NOMAD_PERSISTENT")
        .map(|v| v == "true" || v == "1")
        .unwrap_or(false);

    let config = EchoClientConfig {
        server_addr,
        server_public_key,
        bind_addr: "0.0.0.0:0".parse()?,
        client_keypair: None, // Generate fresh keypair
        persistent,
    };

    let health_state = HealthState::client();

    // Start health server in background
    let health_addr: SocketAddr = format!("0.0.0.0:{}", health_port).parse()?;
    let health_state_clone = health_state.clone();
    tokio::spawn(async move {
        if let Err(e) = start_health_server(health_addr, health_state_clone).await {
            eprintln!("Health server error: {}", e);
        }
    });

    // Connect and run client
    let mut client = EchoClient::new(config.clone());
    client.connect().await?;
    health_state.set_connected(true).await;

    eprintln!("Echo client connected with encrypted session.");

    if config.persistent {
        // Persistent mode - stay connected and read from stdin
        client.run_persistent().await?;
    } else {
        // Test mode - send test messages and exit
        let test_messages = [
            "Hello, NOMAD!",
            "Echo test 1",
            "Echo test 2",
            "Testing state sync...",
            "Goodbye!",
        ];

        for msg in &test_messages {
            match client.echo(msg.as_bytes()).await {
                Ok(response) => {
                    let echoed = String::from_utf8_lossy(&response.message);
                    if response.message == msg.as_bytes() {
                        eprintln!("✓ Echo matched: {:?}", echoed);
                    } else {
                        eprintln!("✗ Echo mismatch: expected {:?}, got {:?}", msg, echoed);
                    }
                }
                Err(e) => {
                    eprintln!("✗ Echo failed: {}", e);
                    health_state.set_healthy(false).await;
                }
            }

            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        }

        eprintln!("Echo client test complete");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_base64() {
        let result = decode_base64("SGVsbG8=").unwrap();
        assert_eq!(result, b"Hello");
    }

    #[test]
    fn test_encode_base64() {
        let result = encode_base64(b"Hello");
        assert_eq!(result, "SGVsbG8=");
    }

    #[test]
    fn test_base64_roundtrip() {
        let original = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let encoded = encode_base64(&original);
        let decoded = decode_base64(&encoded).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn test_base64_32_bytes() {
        let key = [0xab; 32];
        let encoded = encode_base64(&key);
        let decoded = decode_base64(&encoded).unwrap();
        assert_eq!(decoded.len(), 32);
        assert_eq!(decoded, key);
    }

    #[test]
    fn test_parse_key_zeros() {
        // When env var is not set, should return None
        let key = parse_key("NONEXISTENT_KEY_12345");
        assert!(key.is_none());
    }
}
