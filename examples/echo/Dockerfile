# NOMAD Echo Example - Optimized Multi-Stage Build
#
# Uses cargo-chef for dependency caching (much faster rebuilds)
#
# Build targets:
#   docker build -f examples/echo/Dockerfile --target server -t nomad-echo-server .
#   docker build -f examples/echo/Dockerfile --target client -t nomad-echo-client .
#
# Run:
#   docker run -p 19999:19999/udp -p 8080:8080 nomad-echo-server
#   docker run -e NOMAD_SERVER_HOST=host.docker.internal nomad-echo-client

# =============================================================================
# Stage 1: Chef base - Install cargo-chef and build tools
# =============================================================================
FROM rust:1.85-bookworm AS chef

RUN rustup default nightly-2025-04-15 && \
    cargo install cargo-chef --locked && \
    apt-get update && \
    apt-get install -y --no-install-recommends lld clang && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Use lld for faster linking
ENV RUSTFLAGS="-C link-arg=-fuse-ld=lld"

# =============================================================================
# Stage 2: Planner - Analyze dependencies
# =============================================================================
FROM chef AS planner

COPY Cargo.toml Cargo.lock ./
COPY src/ src/
COPY examples/echo/ examples/echo/

RUN cargo chef prepare --recipe-path recipe.json

# =============================================================================
# Stage 3: Builder - Build dependencies (cached) then application
# =============================================================================
FROM chef AS builder

# Copy recipe and build dependencies first (cached layer)
COPY --from=planner /build/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json -p nomad-echo

# Copy source and build application
COPY Cargo.toml Cargo.lock ./
COPY src/ src/
COPY examples/echo/ examples/echo/

RUN cargo build --release -p nomad-echo && \
    strip /build/target/release/nomad-echo

# =============================================================================
# Stage 4: Runtime - Minimal production image
# =============================================================================
FROM debian:bookworm-slim AS runtime

RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates && \
    apt-get autoremove -y && \
    apt-get clean -y && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/nomad-echo /usr/local/bin/

# Default environment
ENV NOMAD_MODE=server \
    NOMAD_SERVER_PORT=19999 \
    NOMAD_HEALTH_PORT=8080 \
    NOMAD_BIND_ADDR=0.0.0.0:19999

EXPOSE 19999/udp
EXPOSE 8080/tcp

ENTRYPOINT ["/usr/local/bin/nomad-echo"]

# =============================================================================
# Stage 5: Server target
# =============================================================================
FROM runtime AS server
ENV NOMAD_MODE=server \
    NOMAD_TEST_MODE=true

# =============================================================================
# Stage 6: Client target
# =============================================================================
FROM runtime AS client
ENV NOMAD_MODE=client \
    NOMAD_SERVER_HOST=127.0.0.1 \
    NOMAD_SERVER_PUBLIC_KEY=gqNRjwG8OsClvG2vWuafYeERaM95Pk0rTLmFAjh6JDo=
