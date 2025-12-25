# Tentacle t2-transport: Transport Layer

## Status: COMPLETE

## Scope
- `crates/nomad-transport/` - Transport layer implementation

## Reference Specs
- `../nomad-specs/specs/2-TRANSPORT.md` - Frames, RTT, pacing, migration

## Tasks

### frame.rs - Frame Encoding/Decoding
- [x] Implement `DataFrameHeader` encode/decode (16 bytes)
- [x] Implement `PayloadHeader` encode/decode (timestamp, echo, length)
- [x] Implement `CloseFrame` encoding
- [x] Build AAD for AEAD (16-byte header)
- [x] Frame type enum and flags

### connection.rs - Connection State Machine
- [x] Define `ConnectionState` struct (session_id, nonces, window, etc.)
- [x] Implement state transitions (Handshaking → Established → Closing → Closed)
- [x] Anti-replay window (`NonceWindow` with 2048-bit sliding window)
- [x] Connection lifecycle management

### timing.rs - RTT Estimation (RFC 6298)
- [x] Implement `RttEstimator` with SRTT, RTTVAR, RTO
- [x] First sample initialization (SRTT = sample, RTTVAR = sample/2)
- [x] Subsequent updates (α=0.125, β=0.25)
- [x] RTO calculation with MIN_RTO=100ms, MAX_RTO=60000ms
- [x] Exponential backoff support
- [x] `TimestampTracker` for RTT measurement via echo

### pacing.rs - Frame Rate Limiting
- [x] MIN_FRAME_INTERVAL = max(SRTT/2, 20ms)
- [x] COLLECTION_INTERVAL = 8ms batching
- [x] DELAYED_ACK_TIMEOUT = 100ms
- [x] MAX_FRAME_RATE = 50 Hz hard cap
- [x] Implement `FramePacer` with `poll()` returning `PacerAction`
- [x] `RetransmitController` with backoff

### migration.rs - IP Roaming
- [x] Update remote endpoint on valid frame from new address
- [x] Anti-amplification: 3× limit before validation
- [x] Rate limit migrations (1/sec per subnet)
- [x] Subnet extraction for IPv4 (/24) and IPv6 (/48)

### socket.rs - Async UDP
- [x] Wrap `tokio::net::UdpSocket`
- [x] `NomadSocket` with async send/recv
- [x] `NomadSocketBuilder` for configuration
- [x] MTU considerations

### error.rs - Error Types
- [x] `TransportError` enum with all transport-level errors
- [x] Silent drop classification
- [x] Fatal error classification

### Tests
- [x] Frame encoding roundtrip tests (10 tests)
- [x] RTT estimator tests (8 tests)
- [x] Pacing algorithm tests (9 tests)
- [x] Connection state tests (6 tests)
- [x] Migration tests (7 tests)
- [x] Socket tests (5 tests)
- [x] Error classification tests (3 tests)
- **Total: 51 tests passing**

## Blocked
(none)

## Notes
- All implementations follow 2-TRANSPORT.md specification exactly
- Uses let-chains (Rust 2024 edition feature) for cleaner conditionals
- Silent drops for invalid/replayed frames per spec
- Ready for integration with t1-crypto (session keys) and t3-sync (sync messages)
