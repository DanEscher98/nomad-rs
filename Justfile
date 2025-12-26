# NOMAD Protocol - Build Commands

# Default target
default: check

# Check crate (fast compile check)
check:
    cargo check --all-features

# Build crate
build:
    cargo build --all-features

# Build in release mode
build-release:
    cargo build --all-features --release

# Run all tests
test:
    cargo test --all-features

# Run lints
lint:
    cargo clippy --all-features -- -D warnings

# Format code
fmt:
    cargo fmt

# Check formatting
fmt-check:
    cargo fmt -- --check

# Full pre-commit check (build + lint + test)
pre-commit: fmt-check lint test

# =============================================================================
# Documentation
# =============================================================================

# Generate documentation
doc:
    cargo doc --all-features --no-deps

# Generate and open documentation
doc-open:
    cargo doc --all-features --no-deps --open

# Publish docs to docs/ directory (for GitHub Pages)
doc-publish:
    cargo doc --all-features --no-deps --release
    rm -rf docs
    cp -r target/doc docs
    echo '<!DOCTYPE html><html><head><meta charset="utf-8"><meta http-equiv="refresh" content="0; url=nomad_protocol/index.html"><title>NOMAD Protocol</title></head><body><p>Redirecting...</p></body></html>' > docs/index.html
    @echo "Documentation published to docs/"

# Clean build artifacts
clean:
    cargo clean

# =============================================================================
# Echo example commands
# =============================================================================

# Build echo example
echo-build:
    cargo build --manifest-path examples/echo/Cargo.toml

# Run echo server (test mode)
echo-server:
    NOMAD_MODE=server NOMAD_TEST_MODE=true cargo run --manifest-path examples/echo/Cargo.toml

# Run echo client (test mode)
echo-client:
    NOMAD_MODE=client NOMAD_SERVER_PUBLIC_KEY=gqNRjwG8OsClvG2vWuafYeERaM95Pk0rTLmFAjh6JDo= cargo run --manifest-path examples/echo/Cargo.toml

# Generate keypair
echo-keygen:
    cargo run --manifest-path examples/echo/Cargo.toml --bin keygen

# =============================================================================
# Docker Builds
# =============================================================================

# Build x86 server
docker-server:
    docker build -f examples/echo/Dockerfile.server-x86 -t nomad-echo-server .

# Build ARM64 client binary only (cross-compiled, no QEMU needed)
docker-client:
    docker build -f examples/echo/Dockerfile.client-arm --target binary -o type=local,dest=./out .
    @echo "ARM64 binary extracted to: out/nomad-echo"

# Build ARM64 client container (cross-compile + ARM64 runtime)
docker-client-qemu:
    docker build -f examples/echo/Dockerfile.client-arm -t nomad-client-arm .

# Build both (server container + client binary)
docker-all: docker-server docker-client

# =============================================================================
# ARM64 Testing (Cortex-X4 / Samsung Tab S10)
# =============================================================================

# Setup QEMU for ARM emulation (run once)
arm-setup:
    docker run --rm --privileged multiarch/qemu-user-static --reset -p yes
    @echo "QEMU binfmt configured for ARM64 emulation"

# Run tests on ARM64 using cross
arm-test:
    cross test --target aarch64-unknown-linux-gnu --all-features

# Run specific test module on ARM64
arm-test-module module:
    cross test --target aarch64-unknown-linux-gnu --all-features {{module}}

# Extract static ARM64 binary for Android
arm-extract:
    docker build -f examples/echo/Dockerfile.client-arm --target binary -o type=local,dest=./out .
    @echo "Binary extracted to: out/nomad-echo"
    @file out/nomad-echo 2>/dev/null || true

# Run ARM64 client in QEMU (connects to host.docker.internal)
arm-run:
    docker run --rm -it --platform linux/arm64 \
        -e NOMAD_SERVER_HOST=host.docker.internal \
        nomad-client-arm

# =============================================================================
# End-to-end testing (server x86 + client ARM in QEMU)
# =============================================================================

# Start x86 server in background
e2e-server:
    docker run -d --name nomad-server -p 19999:19999/udp -p 8080:8080 nomad-echo-server
    @echo "Server started. Health: http://localhost:8080/health"
    @echo "Stop with: just e2e-stop"

# Run ARM client against local server (requires: just docker-client-qemu)
e2e-client:
    docker run --rm --platform linux/arm64 \
        --add-host=host.docker.internal:host-gateway \
        -e NOMAD_SERVER_HOST=host.docker.internal \
        nomad-client-arm

# Full E2E: build both, start server, run client
e2e-run: docker-server docker-client-qemu e2e-server
    @echo "Running ARM client against x86 server..."
    docker run --rm --platform linux/arm64 \
        --add-host=host.docker.internal:host-gateway \
        -e NOMAD_SERVER_HOST=host.docker.internal \
        nomad-client-arm

# Stop and cleanup server
e2e-stop:
    -docker stop nomad-server
    -docker rm nomad-server

# =============================================================================
# Octopus-dev commands (if using parallel development)
# =============================================================================

# Show all tentacle status
octopus-status:
    bash ~/.claude/skills/octopus-dev/scripts/status.sh 2>/dev/null || echo "octopus-dev not configured"

# List all worktrees
worktrees:
    git worktree list
