# Plan: Centralized Telemetry and Metrics System

## Phase 1: Foundation & Logging [checkpoint: bbb99f3]
- [x] Task: Set up `tracing-subscriber` in `ferritedb-server` main entry point with JSON formatting support. bbd32d7
- [x] Task: Create a `TelemetryConfig` struct in `ferritedb-core` to manage log levels and formats. b978bcb
- [x] Task: Replace all `println!` and `eprintln!` calls in `ferritedb-server` with `tracing` macros (info!, error!, etc.). 4a8534a
- [x] Task: Implement request ID middleware in `ferritedb-server` to attach a unique ID to every request span. ef71a23
- [x] Task: Conductor - User Manual Verification 'Foundation & Logging' (Protocol in workflow.md) bbb99f3

## Phase 2: Metrics Infrastructure
- [ ] Task: Add `metrics` and `metrics-exporter-prometheus` dependencies to `ferritedb-server` and `ferritedb-core`.
- [ ] Task: Initialize the Prometheus recorder in `ferritedb-server` startup logic.
- [ ] Task: Create a `/metrics` endpoint in `ferritedb-server` that returns the rendered Prometheus text format.
- [ ] Task: Conductor - User Manual Verification 'Metrics Infrastructure' (Protocol in workflow.md)

## Phase 3: Instrumentation
- [ ] Task: Instrument HTTP handlers in `ferritedb-server` to record request duration (histogram) and counts (counter) by status code.
- [ ] Task: Instrument database queries in `ferritedb-core/src/database.rs` to record query execution time.
- [ ] Task: Instrument authentication logic in `ferritedb-core/src/auth.rs` to count successful and failed login attempts.
- [ ] Task: Instrument storage operations in `ferritedb-storage` to track file upload/download sizes and latencies.
- [ ] Task: Conductor - User Manual Verification 'Instrumentation' (Protocol in workflow.md)

## Phase 4: Validation & Documentation
- [ ] Task: Verify that the `/metrics` endpoint returns valid Prometheus data using `curl` or a test script.
- [ ] Task: Verify that logs are being output in the configured JSON format with request IDs attached.
- [ ] Task: Update `docs/OPERATIONS.md` (or create it) to document the available metrics and how to configure logging.
- [ ] Task: Conductor - User Manual Verification 'Validation & Documentation' (Protocol in workflow.md)
