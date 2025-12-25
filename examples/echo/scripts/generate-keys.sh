#!/usr/bin/env bash
# =============================================================================
# NOMAD Echo - Key Generation Script
# =============================================================================
#
# This script demonstrates how to generate and configure X25519 keypairs
# for NOMAD protocol connections. The Noise_IK handshake requires:
#
#   - Server: Has a static keypair (private + public)
#   - Client: Knows the server's PUBLIC key (for identity verification)
#
# Key Exchange Flow:
#   1. Server generates keypair, shares public key out-of-band
#   2. Client receives server's public key (e.g., via config file, env var)
#   3. Client connects using Noise_IK, encrypting to server's public key
#   4. Server decrypts with private key, both derive session keys
#
# =============================================================================

set -euo pipefail

# -----------------------------------------------------------------------------
# Option 1: Use Test Mode (Deterministic Keys for CI/Testing)
# -----------------------------------------------------------------------------
#
# For conformance testing, use NOMAD_TEST_MODE=true which uses a hardcoded
# keypair. This ensures reproducible tests across environments.
#
# Test Private Key (hex):
#   48 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f
#   10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 7f
#
# Test Public Key (derived via X25519, base64):
#   gqNRjwG8OsClvG2vWuafYeERaM95Pk0rTLmFAjh6JDo=
#
# WARNING: These keys are PUBLIC and should NEVER be used in production!

echo "=============================================="
echo "NOMAD Echo - Key Configuration Guide"
echo "=============================================="
echo ""

# -----------------------------------------------------------------------------
# Option 2: Generate Fresh Keypair (Production Use)
# -----------------------------------------------------------------------------
#
# For production, generate a fresh random keypair. The server keeps the
# private key secret; the public key is shared with authorized clients.

echo "=== Option 1: Test Mode (for CI/conformance testing) ==="
echo ""
echo "Server configuration:"
echo "  export NOMAD_TEST_MODE=true"
echo "  export NOMAD_MODE=server"
echo ""
echo "Client configuration:"
echo "  export NOMAD_MODE=client"
echo "  export NOMAD_SERVER_PUBLIC_KEY=gqNRjwG8OsClvG2vWuafYeERaM95Pk0rTLmFAjh6JDo="
echo "  export NOMAD_SERVER_HOST=<server-ip-or-hostname>"
echo ""

echo "=== Option 2: Generate Fresh Keypair (for production) ==="
echo ""

# Check if we can generate keys using openssl (commonly available)
if command -v openssl &> /dev/null; then
    echo "Generating fresh X25519 keypair using OpenSSL..."
    echo ""

    # Generate X25519 private key in PEM format
    TEMP_DIR=$(mktemp -d)
    openssl genpkey -algorithm X25519 -out "$TEMP_DIR/private.pem" 2>/dev/null

    # Extract raw private key bytes (32 bytes after ASN.1 header)
    # The PEM contains: 30 2e 02 01 00 30 05 06 03 2b 65 6e 04 22 04 20 [32 bytes private]
    PRIVATE_KEY_B64=$(openssl pkey -in "$TEMP_DIR/private.pem" -outform DER 2>/dev/null | tail -c 32 | base64)

    # Extract public key
    openssl pkey -in "$TEMP_DIR/private.pem" -pubout -out "$TEMP_DIR/public.pem" 2>/dev/null
    # Public key DER: 30 2a 30 05 06 03 2b 65 6e 03 21 00 [32 bytes public]
    PUBLIC_KEY_B64=$(openssl pkey -in "$TEMP_DIR/private.pem" -pubout -outform DER 2>/dev/null | tail -c 32 | base64)

    rm -rf "$TEMP_DIR"

    echo "Generated keypair:"
    echo ""
    echo "  Private Key (base64, KEEP SECRET!):"
    echo "    $PRIVATE_KEY_B64"
    echo ""
    echo "  Public Key (base64, share with clients):"
    echo "    $PUBLIC_KEY_B64"
    echo ""
    echo "Server configuration:"
    echo "  export NOMAD_SERVER_PRIVATE_KEY=$PRIVATE_KEY_B64"
    echo "  export NOMAD_SERVER_PUBLIC_KEY=$PUBLIC_KEY_B64"
    echo "  export NOMAD_MODE=server"
    echo ""
    echo "Client configuration:"
    echo "  export NOMAD_MODE=client"
    echo "  export NOMAD_SERVER_PUBLIC_KEY=$PUBLIC_KEY_B64"
    echo "  export NOMAD_SERVER_HOST=<server-ip-or-hostname>"
    echo ""
else
    echo "OpenSSL not found. Install it or use the Rust-based method below."
    echo ""
fi

# -----------------------------------------------------------------------------
# Option 3: Use the NOMAD server to generate keys
# -----------------------------------------------------------------------------
echo "=== Option 3: Let the server generate keys ==="
echo ""
echo "When starting without NOMAD_TEST_MODE or NOMAD_SERVER_PRIVATE_KEY,"
echo "the server generates a fresh keypair and prints the public key:"
echo ""
echo "  NOMAD_MODE=server cargo run -p nomad-echo"
echo ""
echo "Output:"
echo "  === Server Public Key (for clients) ==="
echo "  <base64-encoded-public-key>"
echo "  ========================================"
echo ""
echo "Copy this key to your client's NOMAD_SERVER_PUBLIC_KEY environment variable."
echo ""

# -----------------------------------------------------------------------------
# Docker Compose Example
# -----------------------------------------------------------------------------
echo "=== Docker Compose Configuration ==="
echo ""
echo "For Docker-based testing, the images are pre-configured with test keys:"
echo ""
cat << 'EOF'
# docker-compose.yml
services:
  server:
    image: nomad-echo-server
    environment:
      - NOMAD_MODE=server
      - NOMAD_TEST_MODE=true  # Uses deterministic test keypair
    ports:
      - "19999:19999/udp"
      - "8080:8080"

  client:
    image: nomad-echo-client
    environment:
      - NOMAD_MODE=client
      - NOMAD_SERVER_HOST=server
      - NOMAD_SERVER_PORT=19999
      # Pre-configured with test public key in Dockerfile
    depends_on:
      - server
EOF
echo ""

# -----------------------------------------------------------------------------
# Security Notes
# -----------------------------------------------------------------------------
echo "=== Security Notes ==="
echo ""
echo "1. NEVER use test keys (NOMAD_TEST_MODE) in production"
echo "2. Store private keys securely (env vars, secrets manager, HSM)"
echo "3. Distribute public keys via secure out-of-band channels"
echo "4. Rotate keys periodically (generate new keypair, update clients)"
echo "5. The Noise_IK pattern provides mutual authentication once connected"
echo ""

# -----------------------------------------------------------------------------
# Quick Test Commands
# -----------------------------------------------------------------------------
echo "=== Quick Test Commands ==="
echo ""
echo "# Terminal 1 - Start server with test keys:"
echo "NOMAD_MODE=server NOMAD_TEST_MODE=true cargo run -p nomad-echo"
echo ""
echo "# Terminal 2 - Connect client with test public key:"
echo "NOMAD_MODE=client NOMAD_SERVER_PUBLIC_KEY=gqNRjwG8OsClvG2vWuafYeERaM95Pk0rTLmFAjh6JDo= cargo run -p nomad-echo"
echo ""
echo "# Persistent client mode (interactive):"
echo "NOMAD_MODE=client NOMAD_PERSISTENT=true NOMAD_SERVER_PUBLIC_KEY=gqNRjwG8OsClvG2vWuafYeERaM95Pk0rTLmFAjh6JDo= cargo run -p nomad-echo"
echo ""
