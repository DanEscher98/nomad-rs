# NOMAD Echo Example - Conformance Testing Dockerfile
#
# Standalone build (from nomad-rs root):
#   docker build -f examples/echo/Dockerfile --target server -t nomad-echo-server .
#   docker build -f examples/echo/Dockerfile --target client -t nomad-echo-client .
#
# Standalone run:
#   docker run -p 19999:19999/udp -p 8080:8080 -e NOMAD_MODE=server nomad-echo-server
#   docker run -e NOMAD_MODE=client -e NOMAD_SERVER_HOST=host.docker.internal nomad-echo-client
#
# With nomad-specs docker-compose (from nomad-specs/docker/):
#   SERVER_CONTEXT=rs-impl SERVER_DOCKERFILE=examples/echo/Dockerfile \
#   CLIENT_CONTEXT=rs-impl CLIENT_DOCKERFILE=examples/echo/Dockerfile \
#   docker compose up -d

# Stage 1: Build (using nightly for Rust 2024 edition)
FROM rustlang/rust:nightly-bookworm AS builder

WORKDIR /build

# Copy workspace manifests first for layer caching
COPY Cargo.toml Cargo.lock ./
COPY examples/echo/Cargo.toml examples/echo/

# Create dummy source files for dependency caching
RUN mkdir -p src && echo "pub fn dummy() {}" > src/lib.rs && \
    mkdir -p examples/echo/src && echo "fn main() {}" > examples/echo/src/main.rs && \
    mkdir -p examples/echo/src/bin && echo "fn main() {}" > examples/echo/src/bin/keygen.rs

# Build dependencies only (cached layer)
RUN cargo build --release -p nomad-echo 2>/dev/null || true

# Copy real source code
COPY src/ src/
COPY examples/echo/src/ examples/echo/src/

# Touch source files to force rebuild
RUN touch src/*.rs src/**/*.rs examples/echo/src/*.rs 2>/dev/null || true

# Build the echo binary
RUN cargo build --release -p nomad-echo

# Stage 2: Runtime (minimal image)
FROM debian:bookworm-slim AS runtime

RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates curl && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/nomad-echo /usr/local/bin/

# Default environment
ENV NOMAD_MODE=server
ENV NOMAD_SERVER_PORT=19999
ENV NOMAD_HEALTH_PORT=8080
ENV NOMAD_BIND_ADDR=0.0.0.0:19999

# Expose ports
EXPOSE 19999/udp
EXPOSE 8080/tcp

ENTRYPOINT ["/usr/local/bin/nomad-echo"]

# Stage 3: Server target
FROM runtime AS server
ENV NOMAD_MODE=server
# Enable test mode for deterministic keypair in conformance testing
ENV NOMAD_TEST_MODE=true

# Stage 4: Client target
FROM runtime AS client
ENV NOMAD_MODE=client
ENV NOMAD_SERVER_HOST=127.0.0.1
# Use test mode public key (derived from test private key)
# This matches the server's deterministic keypair when NOMAD_TEST_MODE=true
ENV NOMAD_SERVER_PUBLIC_KEY=gqNRjwG8OsClvG2vWuafYeERaM95Pk0rTLmFAjh6JDo=
