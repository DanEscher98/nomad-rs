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

# Build echo Docker images
echo-docker:
    docker build -f examples/echo/Dockerfile --target server -t nomad-echo-server .
    docker build -f examples/echo/Dockerfile --target client -t nomad-echo-client .

# =============================================================================
# Octopus-dev commands (if using parallel development)
# =============================================================================

# Show all tentacle status
octopus-status:
    bash ~/.claude/skills/octopus-dev/scripts/status.sh 2>/dev/null || echo "octopus-dev not configured"

# List all worktrees
worktrees:
    git worktree list
