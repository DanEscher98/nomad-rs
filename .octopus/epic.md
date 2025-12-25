# Epic: NOMAD Protocol Rust Implementation

## Acceptance Criteria

- [ ] All 5 spec documents implemented (0-PROTOCOL through 4-EXTENSIONS)
- [ ] Workspace compiles with `cargo check --workspace`
- [ ] Test vectors pass (from `nomad-specs/specs/generate_vectors.py`)
- [ ] Echo example (`nomad.echo.v1`) runs as Docker container per CONFORMANCE.md
- [ ] Client can connect to server, complete handshake, sync state

## Exit Criteria

- [ ] All ACs demonstrated
- [ ] All tentacles merged
- [ ] `cargo check --workspace` passes
- [ ] `cargo test --workspace` passes
- [ ] No P0/P1 bugs

## Out of Scope

- `nomad-terminal` crate (for MoshiMoshi later)
- Terminal-specific extensions (scrollback, prediction)
- Production-ready error handling (focus on correctness first)

## Technical Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Rust Edition | 2024 | User preference |
| Async Runtime | tokio | Industry standard for async UDP |
| Crypto | snow + chacha20poly1305 | Spec requirement |
| Error handling | thiserror | Clean error types |
| Health check | axum | Lightweight, async-first |

## Tentacle Breakdown

| ID | Scope | Dependencies | Status |
|----|-------|--------------|--------|
| t1-crypto | crates/nomad-core, crates/nomad-crypto | none | pending |
| t2-transport | crates/nomad-transport | t1-crypto (traits) | pending |
| t3-sync | crates/nomad-sync, crates/nomad-extensions | t2-transport (frames) | pending |
| t4-api | crates/nomad-client, crates/nomad-server, examples/echo | t3-sync (engine) | pending |

## Key Specs Reference

- `../nomad-specs/specs/0-PROTOCOL.md` - Overview, constants
- `../nomad-specs/specs/1-SECURITY.md` - Noise_IK, AEAD, rekeying
- `../nomad-specs/specs/2-TRANSPORT.md` - Frames, RTT, pacing
- `../nomad-specs/specs/3-SYNC.md` - State versioning, diffs
- `../nomad-specs/specs/4-EXTENSIONS.md` - Compression
