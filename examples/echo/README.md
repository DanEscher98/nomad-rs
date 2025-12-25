# NOMAD Echo Example

A minimal echo server/client implementation for NOMAD protocol conformance testing. Demonstrates the complete protocol stack including Noise_IK handshake, encrypted communication, and state synchronization.

## Features

- **Noise_IK Handshake**: Secure key exchange with server identity verification
- **Encrypted Communication**: All messages encrypted with XChaCha20-Poly1305
- **State Synchronization**: Implements `nomad.echo.v1` state type
- **Health Checks**: HTTP endpoint for container orchestration
- **Test Mode**: Deterministic keypair for reproducible CI testing
- **Persistent Mode**: Interactive client for manual testing

## Quick Start

### Build

```bash
cargo build -p nomad-echo
```

### Run Server

```bash
# Generate fresh keypair (prints public key for clients)
NOMAD_MODE=server cargo run -p nomad-echo
```

Output:
```
=== Server Public Key (for clients) ===
gqNRjwG8OsClvG2vWuafYeERaM95Pk0rTLmFAjh6JDo=
========================================
Echo server listening on 0.0.0.0:19999
```

### Run Client

```bash
# Connect using server's public key
NOMAD_MODE=client \
NOMAD_SERVER_PUBLIC_KEY=<key-from-server> \
cargo run -p nomad-echo
```

Output:
```
✓ Echo matched: "Hello, NOMAD!"
✓ Echo matched: "Echo test 1"
✓ Echo matched: "Echo test 2"
✓ Echo matched: "Testing state sync..."
✓ Echo matched: "Goodbye!"
Echo client test complete
```

## Environment Variables

### Common

| Variable | Default | Description |
|----------|---------|-------------|
| `NOMAD_MODE` | `server` | Run as `server` or `client` |
| `NOMAD_SERVER_PORT` | `19999` | UDP port for NOMAD protocol |
| `NOMAD_HEALTH_PORT` | `8080` | HTTP port for health checks |

### Server Only

| Variable | Default | Description |
|----------|---------|-------------|
| `NOMAD_BIND_ADDR` | `0.0.0.0:19999` | Address to bind server |
| `NOMAD_TEST_MODE` | `false` | Use deterministic test keypair |
| `NOMAD_SERVER_PRIVATE_KEY` | (generated) | Base64-encoded private key |
| `NOMAD_SERVER_PUBLIC_KEY` | (derived) | Base64-encoded public key |

### Client Only

| Variable | Default | Description |
|----------|---------|-------------|
| `NOMAD_SERVER_HOST` | `127.0.0.1` | Server hostname or IP |
| `NOMAD_SERVER_PUBLIC_KEY` | (required) | Server's base64 public key |
| `NOMAD_PERSISTENT` | `false` | Stay connected, read from stdin |

## Key Management

### Option 1: Auto-Generate (Development)

Start the server without keys - it generates a fresh keypair and prints the public key:

```bash
NOMAD_MODE=server cargo run -p nomad-echo
# Copy the printed public key to client
```

### Option 2: Test Mode (CI/Conformance)

Use deterministic keys for reproducible testing:

```bash
# Server
NOMAD_MODE=server NOMAD_TEST_MODE=true cargo run -p nomad-echo

# Client (test public key is known)
NOMAD_MODE=client \
NOMAD_SERVER_PUBLIC_KEY=gqNRjwG8OsClvG2vWuafYeERaM95Pk0rTLmFAjh6JDo= \
cargo run -p nomad-echo
```

### Option 3: Pre-Generated Keys (Production)

Generate and manage your own keypair:

```bash
# Generate keypair
cargo run -p nomad-echo --bin keygen

# Or for test keys
cargo run -p nomad-echo --bin keygen -- --test
```

Output:
```
Private Key (base64) - KEEP SECRET!
────────────────────────────────────────────────────────────────────
<private-key>

Public Key (base64) - Share with authorized clients
────────────────────────────────────────────────────────────────────
<public-key>
```

Use these keys:
```bash
# Server
NOMAD_MODE=server \
NOMAD_SERVER_PRIVATE_KEY=<private-key> \
NOMAD_SERVER_PUBLIC_KEY=<public-key> \
cargo run -p nomad-echo

# Client
NOMAD_MODE=client \
NOMAD_SERVER_PUBLIC_KEY=<public-key> \
cargo run -p nomad-echo
```

## Test Mode Keys

For conformance testing, these deterministic keys are used when `NOMAD_TEST_MODE=true`:

| Key | Base64 |
|-----|--------|
| Private | `SAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHn8=` |
| Public | `gqNRjwG8OsClvG2vWuafYeERaM95Pk0rTLmFAjh6JDo=` |

**WARNING**: These keys are PUBLIC. Never use in production!

## Persistent Client Mode

For interactive testing, use persistent mode to send custom messages:

```bash
NOMAD_MODE=client \
NOMAD_PERSISTENT=true \
NOMAD_SERVER_PUBLIC_KEY=<key> \
cargo run -p nomad-echo
```

Then type messages and press Enter:
```
Hello World
✓ Echo matched: "Hello World"
Testing 123
✓ Echo matched: "Testing 123"
^C
```

## Docker

### Build Images

```bash
# From nomad-rs root
docker build -f examples/echo/Dockerfile --target server -t nomad-echo-server .
docker build -f examples/echo/Dockerfile --target client -t nomad-echo-client .
```

### Run Standalone

```bash
# Server (test mode enabled by default in Docker)
docker run -p 19999:19999/udp -p 8080:8080 nomad-echo-server

# Client (connects to host)
docker run --add-host=host.docker.internal:host-gateway \
  -e NOMAD_SERVER_HOST=host.docker.internal \
  nomad-echo-client
```

### Docker Compose

```yaml
services:
  server:
    image: nomad-echo-server
    ports:
      - "19999:19999/udp"
      - "8080:8080"

  client:
    image: nomad-echo-client
    environment:
      - NOMAD_SERVER_HOST=server
    depends_on:
      - server
```

### With nomad-specs Conformance Testing

```bash
cd ../nomad-specs/docker

# Set implementation paths
export SERVER_CONTEXT=rs-impl
export SERVER_DOCKERFILE=examples/echo/Dockerfile
export CLIENT_CONTEXT=rs-impl
export CLIENT_DOCKERFILE=examples/echo/Dockerfile

docker compose up
```

## Health Checks

Both server and client expose HTTP health endpoints:

```bash
# Check health
curl http://localhost:8080/health
# {"status":"healthy","mode":"server","connected":true}

# Liveness probe
curl http://localhost:8080/healthz
# OK

# Readiness probe
curl http://localhost:8080/ready
# OK
```

## Protocol Details

### State Type

```
nomad.echo.v1
```

### Message Flow

1. **Handshake Init** (Client → Server)
   - Type: `0x00`
   - Payload: Noise_IK message with state type ID

2. **Handshake Response** (Server → Client)
   - Type: `0x01`
   - Payload: Noise_IK response with session ID

3. **Encrypted Data** (Bidirectional)
   - Type: `0x03`
   - Header: `[session_id:6][nonce:8]`
   - Payload: Encrypted `[sequence:8][message...]`

### Echo Behavior

- Client sends message with incrementing sequence number
- Server echoes message back with its own sequence and acknowledgment
- Client verifies echoed content matches original

## Project Structure

```
examples/echo/
├── Cargo.toml
├── Dockerfile
├── README.md
├── scripts/
│   └── generate-keys.sh    # Key generation helper
└── src/
    ├── main.rs             # Entry point, config parsing
    ├── server.rs           # Echo server implementation
    ├── client.rs           # Echo client implementation
    ├── state.rs            # EchoState (SyncState impl)
    ├── health.rs           # HTTP health endpoints
    └── bin/
        └── keygen.rs       # Key generation utility
```

## Troubleshooting

### "Handshake timeout"

- Verify server is running and reachable
- Check firewall allows UDP on port 19999
- Ensure `NOMAD_SERVER_HOST` is correct

### "decrypt error" during handshake

- Client has wrong server public key
- Verify `NOMAD_SERVER_PUBLIC_KEY` matches server's key
- If using test mode, ensure both use `NOMAD_TEST_MODE=true`

### "No NOMAD_SERVER_PUBLIC_KEY provided"

- Client requires server's public key for Noise_IK
- Get key from server output or use test mode

### Docker client can't connect

- Use `--add-host=host.docker.internal:host-gateway` for host networking
- Or use Docker Compose with service networking
