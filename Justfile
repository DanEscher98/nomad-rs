# NOMAD Protocol - Build Commands

# Default target
default: check

# Check all crates (fast compile check)
check:
    cargo check --workspace

# Build all crates
build:
    cargo build --workspace

# Build in release mode
build-release:
    cargo build --workspace --release

# Run all tests
test:
    cargo test --workspace

# Run lints
lint:
    cargo clippy --workspace -- -D warnings

# Format code
fmt:
    cargo fmt --all

# Check formatting
fmt-check:
    cargo fmt --all -- --check

# Full pre-commit check (build + lint + test)
pre-commit: fmt-check lint test

# Generate documentation
doc:
    cargo doc --workspace --no-deps

# Clean build artifacts
clean:
    cargo clean

# =============================================================================
# Octopus-dev commands
# =============================================================================

# Show all tentacle status
octopus-status:
    bash ~/.claude/skills/octopus-dev/scripts/status.sh

# Spawn a new tentacle worktree
octopus-spawn id scope description="":
    bash ~/.claude/skills/octopus-dev/scripts/spawn-tentacle.sh {{id}} "{{scope}}" "{{description}}"

# Merge a completed tentacle
octopus-merge id:
    bash ~/.claude/skills/octopus-dev/scripts/merge-tentacle.sh {{id}}

# Check for stale tentacles (default 2 hours)
octopus-stale hours="2":
    bash ~/.claude/skills/octopus-dev/scripts/check-stale.sh {{hours}}

# List all worktrees
worktrees:
    git worktree list

# =============================================================================
# Echo example commands
# =============================================================================

# Build echo example
echo-build:
    cargo build -p nomad-echo

# Build echo Docker image (server)
echo-docker-server:
    docker build -t nomad-echo-server --target server examples/echo

# Build echo Docker image (client)
echo-docker-client:
    docker build -t nomad-echo-client --target client examples/echo
