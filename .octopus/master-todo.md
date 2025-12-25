# Master TODO - NOMAD Protocol Implementation

## Active Tentacles

| ID | Description | Scope | Status | Worktree |
|----|-------------|-------|--------|----------|
| t1-crypto | Security layer (core traits + crypto) | crates/nomad-core, crates/nomad-crypto | **READY** | .worktrees/t1-crypto |
| t2-transport | Transport layer | crates/nomad-transport | **READY** | .worktrees/t2-transport |
| t3-sync | Sync layer + extensions | crates/nomad-sync, crates/nomad-extensions | **READY** | .worktrees/t3-sync |
| t4-api | Client/Server + Echo example | crates/nomad-client, crates/nomad-server, examples/echo | **READY** | .worktrees/t4-api |

## Dependency Order

```
t1-crypto (can start immediately - FOUNDATION)
    ↓ publishes: SyncState trait, error types, constants
t2-transport (can start frame encoding independently)
    ↓ publishes: Frame types, ConnectionState
t3-sync (can start message encoding independently)
    ↓ publishes: SyncEngine, SyncTracker
t4-api (depends on all above)
    → produces: working echo example
```

## Contracts Status

- [x] `.octopus/contracts/traits.rs` - Core traits
- [x] `.octopus/contracts/errors.rs` - Error types
- [x] `.octopus/contracts/constants.rs` - Protocol constants
- [x] `.octopus/contracts/frames.rs` - Frame types
- [x] `.octopus/contracts/messages.rs` - Sync message types

## How to Launch Tentacles

Open separate terminals and run:

```bash
# Terminal 2 (t1-crypto - START FIRST, foundation)
cd .worktrees/t1-crypto && claude

# Terminal 3 (t2-transport)
cd .worktrees/t2-transport && claude

# Terminal 4 (t3-sync)
cd .worktrees/t3-sync && claude

# Terminal 5 (t4-api - can start but will wait for dependencies)
cd .worktrees/t4-api && claude
```

## Merged Tentacles

(none yet)
