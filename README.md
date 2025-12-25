# NOMAD Protocol

[![Crates.io](https://img.shields.io/crates/v/nomad-protocol.svg)](https://crates.io/crates/nomad-protocol)
[![Documentation](https://docs.rs/nomad-protocol/badge.svg)](https://docs.rs/nomad-protocol)
[![License](https://img.shields.io/crates/l/nomad-protocol.svg)](LICENSE-MIT)
[![CI](https://github.com/DanEscher98/nomad-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/DanEscher98/nomad-rs/actions)

**N**etwork-**O**ptimized **M**obile **A**pplication **D**atagram

A secure, UDP-based state synchronization protocol designed for real-time applications over unreliable networks. Inspired by [Mosh](https://mosh.org/) but redesigned from scratch with modern cryptography and a generic state synchronization framework.

## Features

- **Security**: End-to-end authenticated encryption using Noise_IK + XChaCha20-Poly1305
- **Mobility**: Seamless IP address migration (WiFi ↔ cellular roaming)
- **Low Latency**: Sub-100ms reconnection, optional client-side prediction
- **Simplicity**: Fixed cryptographic suite, no negotiation complexity
- **Generality**: Application-agnostic state synchronization framework

## Quick Start

Add to your `Cargo.toml`:

```toml
[dependencies]
nomad-protocol = "0.1"
```

### Define Your State Type

```rust
use nomad_protocol::prelude::*;

#[derive(Clone)]
struct GameState {
    players: Vec<Player>,
    score: u32,
}

#[derive(Clone)]
struct GameDiff {
    // Your diff representation
}

impl SyncState for GameState {
    type Diff = GameDiff;
    const STATE_TYPE_ID: &'static str = "com.example.game.v1";

    fn diff_from(&self, old: &Self) -> Self::Diff {
        // Compute idempotent diff
        todo!()
    }

    fn apply_diff(&mut self, diff: &Self::Diff) -> Result<(), ApplyError> {
        // Apply diff (must be idempotent)
        todo!()
    }

    fn encode_diff(diff: &Self::Diff) -> Vec<u8> {
        // Serialize for wire
        todo!()
    }

    fn decode_diff(data: &[u8]) -> Result<Self::Diff, DecodeError> {
        // Deserialize from wire
        todo!()
    }
}
```

### Client Example

```rust
use nomad_protocol::prelude::*;

#[tokio::main]
async fn main() -> Result<(), NomadError> {
    // Connect to server
    let client = NomadClient::<GameState>::builder()
        .server_public_key(server_pubkey)
        .connect("game.example.com:19999")
        .await?;

    // Send state updates
    client.update_state(|state| {
        state.score += 10;
    }).await?;

    Ok(())
}
```

### Server Example

```rust
use nomad_protocol::prelude::*;

#[tokio::main]
async fn main() -> Result<(), NomadError> {
    let server = NomadServer::<GameState>::builder()
        .private_key(server_privkey)
        .bind("0.0.0.0:19999")
        .await?;

    // Accept connections
    while let Some(session) = server.accept().await {
        tokio::spawn(async move {
            handle_session(session).await;
        });
    }

    Ok(())
}
```

## Feature Flags

| Feature | Default | Description |
|---------|---------|-------------|
| `full` | ✓ | Enable all features |
| `client` | ✓ | High-level client API |
| `server` | ✓ | High-level server API |
| `compression` | ✓ | zstd compression support |
| `transport` | ✓ | Transport layer |
| `sync` | ✓ | Sync layer |

Minimal build (core + crypto only):

```toml
[dependencies]
nomad-protocol = { version = "0.1", default-features = false }
```

## Protocol Overview

```
┌─────────────────────────────────────────────────────────────┐
│  APPLICATION     Your App (impl SyncState)                  │
├─────────────────────────────────────────────────────────────┤
│  EXTENSIONS      compression (zstd)                         │
├─────────────────────────────────────────────────────────────┤
│  SYNC LAYER      versioning • idempotent diffs • convergence│
├─────────────────────────────────────────────────────────────┤
│  TRANSPORT       frames • session ID • RTT • keepalive      │
├─────────────────────────────────────────────────────────────┤
│  SECURITY        Noise_IK • XChaCha20-Poly1305 • BLAKE2s    │
├─────────────────────────────────────────────────────────────┤
│  UDP             tokio::net::UdpSocket                      │
└─────────────────────────────────────────────────────────────┘
```

## Cryptographic Suite

NOMAD uses a **fixed** cryptographic suite with **no negotiation**:

| Purpose | Algorithm |
|---------|-----------|
| Key Exchange | X25519 (Noise_IK pattern) |
| AEAD | XChaCha20-Poly1305 |
| Hash | BLAKE2s-256 |
| KDF | HKDF-BLAKE2s |

## Performance Targets

| Metric | Target |
|--------|--------|
| Handshake | < 1 RTT |
| Reconnection | < 100ms |
| Frame rate | 50 Hz max |
| Throughput | > 10 MB/s |

## Crate Structure

This workspace publishes a single crate `nomad-protocol` that contains all functionality. Internal modules:

| Module | Description |
|--------|-------------|
| `core` | Core traits and constants |
| `crypto` | Cryptographic primitives (Noise_IK, XChaCha20-Poly1305) |
| `transport` | Frame encoding, RTT estimation, connection migration |
| `sync` | State synchronization with idempotent diffs |
| `extensions` | Optional extensions (compression) |
| `client` | High-level async client API |
| `server` | High-level async server API |

## Comparison with Mosh

| Feature | NOMAD | Mosh |
|---------|-------|------|
| Encryption | XChaCha20-Poly1305 | AES-OCB |
| Key Exchange | Noise_IK (1-RTT) | Out-of-band (SSH) |
| State Types | Generic (any) | Terminal only |
| Rekeying | Every 2 min | No |
| Forward Secrecy | Yes | No |
| Protocol Version | Extensible | Fixed |

## Specification

The protocol specification is maintained separately. See the `specs/` directory for:

- `0-PROTOCOL.md` - Overview and constants
- `1-SECURITY.md` - Cryptography and handshake
- `2-TRANSPORT.md` - Framing and timing
- `3-SYNC.md` - State synchronization
- `4-EXTENSIONS.md` - Optional extensions

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Contributing

Contributions are welcome! Please read our contributing guidelines before submitting PRs.

## Acknowledgments

- [Mosh](https://mosh.org/) - Original inspiration for state synchronization over UDP
- [WireGuard](https://www.wireguard.com/) - Inspiration for clean cryptographic design
- [Noise Protocol Framework](https://noiseprotocol.org/) - Key exchange pattern
