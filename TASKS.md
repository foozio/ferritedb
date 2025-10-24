# Task Backlog

## Critical
- Replace unsafe `Value::as_object().unwrap()` calls with graceful validation in `crates/core/src/records.rs:86` and `crates/core/src/collections.rs:526`, returning `CoreError::ValidationError` on malformed payloads.
- Rework `parse_filter_expression` to build parameterised SQL (e.g., via SQLx query builder) so `/api/collections/*` queries no longer interpolate user input (`crates/core/src/records.rs:459-475`).
- Pass `state.realtime_manager.clone()` into `websocket_handler` instead of `RealtimeManager::new(...)` (`crates/server/src/realtime.rs:389`) and add an integration test that asserts record writes reach WebSocket subscribers.
- Persist file metadata as structured JSON (serialise/deserialise via `serde_json`) to unblock file download flows (`crates/core/src/records.rs:408-410`, `crates/server/src/files.rs:372-389`).

## High Priority
- Swap `std::sync::Mutex/RwLock` usage in request paths for `tokio::sync` equivalents or redesign to avoid blocking locks (`crates/server/src/routes.rs:692`, `crates/server/src/realtime.rs:209-232`).
- Implement real database/storage readiness checks and surface failures through `/api/readyz` (`crates/server/src/routes.rs:389-400`).
- Remove the `dbg!` call from `SchemaManager::create_collection_with_table` and rely on tracing instrumentation (`crates/core/src/schema_manager.rs:37`).

## Medium Priority
- Expand automated tests around optional features (`s3-storage`, `oauth2`, `image-transforms`) and add smoke tests for `just` recipes that touch those code paths.
- Wire the audit logger into REST handlers so auth, collection, and record mutations emit consistent entries.
- Document and enforce API contract for filter syntax, including numeric/boolean comparisons, and update SDKs accordingly.
