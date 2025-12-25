# Master TODO - NOMAD Protocol Implementation

## Active Tentacles

| ID | Description | Scope | Status | Worktree |
|----|-------------|-------|--------|----------|
| t1-crypto | Security layer (core traits + crypto) | crates/nomad-core, crates/nomad-crypto | pending | .worktrees/t1-crypto |
| t2-transport | Transport layer | crates/nomad-transport | pending | .worktrees/t2-transport |
| t3-sync | Sync layer + extensions | crates/nomad-sync, crates/nomad-extensions | pending | .worktrees/t3-sync |
| t4-api | Client/Server + Echo example | crates/nomad-client, crates/nomad-server, examples/echo | pending | .worktrees/t4-api |

## Dependency Order

```
t1-crypto (can start immediately)
    ↓ publishes: SyncState trait, error types, constants
t2-transport (needs t1 contracts)
    ↓ publishes: Frame types, ConnectionState
t3-sync (needs t2 contracts)
    ↓ publishes: SyncEngine, SyncTracker
t4-api (needs t3 contracts)
    → produces: working echo example
```

## Contracts Status

- [ ] `.octopus/contracts/traits.rs` - Core traits
- [ ] `.octopus/contracts/errors.rs` - Error types
- [ ] `.octopus/contracts/constants.rs` - Protocol constants
- [ ] `.octopus/contracts/frames.rs` - Frame types
- [ ] `.octopus/contracts/messages.rs` - Sync message types

## Merged Tentacles

(none yet)
