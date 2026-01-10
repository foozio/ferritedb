# Plan: Realtime Infrastructure Stability and Resilience

## Phase 1: Configuration & Infrastructure
- [ ] Task: Update `ferritedb-core` config struct (`CoreConfig`) to include `heartbeat_interval` (default: 30s) and `heartbeat_timeout_count` (default: 3).
- [ ] Task: Update `RealtimeManager` in `ferritedb-server` to accept these new configuration parameters.
- [ ] Task: Conductor - User Manual Verification 'Configuration & Infrastructure' (Protocol in workflow.md)

## Phase 2: Heartbeat Implementation
- [ ] Task: Implement the heartbeat loop within the individual WebSocket connection handler in `ferritedb-server/src/realtime.rs`.
    - [ ] Sub-task: Create a periodic tokio interval for sending pings.
    - [ ] Sub-task: Track the "last received pong" timestamp or missed count.
    - [ ] Sub-task: Close the connection stream if the threshold is exceeded.
- [ ] Task: Instrument the heartbeat failure path to log a warning via `tracing`.
- [ ] Task: Conductor - User Manual Verification 'Heartbeat Implementation' (Protocol in workflow.md)

## Phase 3: Cleanup & Verification
- [ ] Task: Verify `RealtimeManager::remove_connection` is called correctly when the heartbeat loop terminates the connection.
- [ ] Task: Add an integration test in `crates/server/tests` simulating an unresponsive client to verify the server closes the connection.
- [ ] Task: Add an integration test verifying the server respects the configured heartbeat interval.
- [ ] Task: Conductor - User Manual Verification 'Cleanup & Verification' (Protocol in workflow.md)
