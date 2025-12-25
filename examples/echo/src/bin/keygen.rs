//! NOMAD Key Generation Utility
//!
//! Generates X25519 keypairs for NOMAD protocol connections.
//!
//! # Usage
//!
//! Generate a fresh random keypair:
//! ```bash
//! cargo run -p nomad-echo --bin keygen
//! ```
//!
//! Show the test mode keypair (for conformance testing):
//! ```bash
//! cargo run -p nomad-echo --bin keygen -- --test
//! ```
//!
//! # Output Format
//!
//! Keys are output in base64 format, ready to use as environment variables:
//! - `NOMAD_SERVER_PRIVATE_KEY` - Server's private key (keep secret!)
//! - `NOMAD_SERVER_PUBLIC_KEY` - Server's public key (share with clients)

use std::env;

/// Base64 encoding alphabet
const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Encode bytes as base64
fn encode_base64(data: &[u8]) -> String {
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

/// Test mode private key (DO NOT USE IN PRODUCTION)
const TEST_PRIVATE_KEY: [u8; 32] = [
    0x48, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x7f,
];

fn main() {
    let args: Vec<String> = env::args().collect();
    let show_test = args.iter().any(|a| a == "--test" || a == "-t");
    let show_help = args.iter().any(|a| a == "--help" || a == "-h");

    if show_help {
        println!("NOMAD Key Generation Utility");
        println!();
        println!("Usage:");
        println!("  keygen           Generate a fresh random keypair");
        println!("  keygen --test    Show the test mode keypair (for CI/conformance)");
        println!();
        println!("Output:");
        println!("  Base64-encoded keys ready for environment variables");
        return;
    }

    println!("╔══════════════════════════════════════════════════════════════════╗");
    println!("║              NOMAD X25519 Key Generation                         ║");
    println!("╚══════════════════════════════════════════════════════════════════╝");
    println!();

    let (private_key, public_key, is_test) = if show_test {
        // Derive public key from test private key
        let secret = x25519_dalek::StaticSecret::from(TEST_PRIVATE_KEY);
        let public = x25519_dalek::PublicKey::from(&secret);
        (TEST_PRIVATE_KEY, *public.as_bytes(), true)
    } else {
        // Generate fresh random keypair
        let secret = x25519_dalek::StaticSecret::random_from_rng(rand::thread_rng());
        let public = x25519_dalek::PublicKey::from(&secret);
        // Note: StaticSecret doesn't expose raw bytes directly in safe API
        // We need to use EphemeralSecret for generation, or work around it
        let private_bytes: [u8; 32] = secret.to_bytes();
        (private_bytes, *public.as_bytes(), false)
    };

    let private_b64 = encode_base64(&private_key);
    let public_b64 = encode_base64(&public_key);

    if is_test {
        println!("⚠️  TEST MODE KEYPAIR - DO NOT USE IN PRODUCTION!");
        println!();
        println!("These keys are PUBLIC and deterministic for conformance testing.");
        println!();
    } else {
        println!("✅ Generated fresh random keypair");
        println!();
    }

    println!("Private Key (base64) - KEEP SECRET!");
    println!("────────────────────────────────────────────────────────────────────");
    println!("{}", private_b64);
    println!();

    println!("Public Key (base64) - Share with authorized clients");
    println!("────────────────────────────────────────────────────────────────────");
    println!("{}", public_b64);
    println!();

    println!("╔══════════════════════════════════════════════════════════════════╗");
    println!("║                     Configuration                                ║");
    println!("╚══════════════════════════════════════════════════════════════════╝");
    println!();

    println!("# Server configuration:");
    if is_test {
        println!("export NOMAD_TEST_MODE=true");
    } else {
        println!("export NOMAD_SERVER_PRIVATE_KEY={}", private_b64);
        println!("export NOMAD_SERVER_PUBLIC_KEY={}", public_b64);
    }
    println!("export NOMAD_MODE=server");
    println!();

    println!("# Client configuration:");
    println!("export NOMAD_MODE=client");
    println!("export NOMAD_SERVER_PUBLIC_KEY={}", public_b64);
    println!("export NOMAD_SERVER_HOST=<server-ip-or-hostname>");
    println!();

    println!("╔══════════════════════════════════════════════════════════════════╗");
    println!("║                     Quick Start                                  ║");
    println!("╚══════════════════════════════════════════════════════════════════╝");
    println!();

    if is_test {
        println!("# Terminal 1 - Start server:");
        println!("NOMAD_MODE=server NOMAD_TEST_MODE=true cargo run -p nomad-echo");
        println!();
        println!("# Terminal 2 - Connect client:");
        println!("NOMAD_MODE=client NOMAD_SERVER_PUBLIC_KEY={} cargo run -p nomad-echo", public_b64);
    } else {
        println!("# Terminal 1 - Start server:");
        println!("NOMAD_MODE=server NOMAD_SERVER_PRIVATE_KEY={} NOMAD_SERVER_PUBLIC_KEY={} cargo run -p nomad-echo", private_b64, public_b64);
        println!();
        println!("# Terminal 2 - Connect client:");
        println!("NOMAD_MODE=client NOMAD_SERVER_PUBLIC_KEY={} cargo run -p nomad-echo", public_b64);
    }
    println!();

    // Print raw hex for debugging (only for test mode)
    if is_test {
        println!("╔══════════════════════════════════════════════════════════════════╗");
        println!("║                     Raw Bytes (Hex)                              ║");
        println!("╚══════════════════════════════════════════════════════════════════╝");
        println!();
        println!("Private Key:");
        print!("  ");
        for (i, b) in private_key.iter().enumerate() {
            print!("{:02x}", b);
            if i % 16 == 15 {
                println!();
                if i < 31 {
                    print!("  ");
                }
            } else {
                print!(" ");
            }
        }
        println!();
        println!("Public Key:");
        print!("  ");
        for (i, b) in public_key.iter().enumerate() {
            print!("{:02x}", b);
            if i % 16 == 15 {
                println!();
                if i < 31 {
                    print!("  ");
                }
            } else {
                print!(" ");
            }
        }
        println!();
    }
}
