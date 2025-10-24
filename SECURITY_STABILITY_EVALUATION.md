# Security & Stability Evaluation

## Strengths
- Solid cryptography defaults: Argon2id password hashing and JWT handling inside `crates/core/src/auth.rs` with configurable TTLs promotes secure auth flows.
- HTTP surface hardening: middleware stack injects security headers, request-size limits, rate limiting, and input validation (`crates/server/src/security.rs`, `crates/server/src/middleware.rs`).
- Storage backend sanitises paths and defends against traversal (`crates/storage/src/local.rs`).
- PII utilities (`crates/core/src/pii.rs`) enable redaction before logging or emitting sensitive data.
- Audit logging and rule engine provide hooks for monitoring and authorization enforcement.

## Critical Findings
- **Unchecked JSON assumptions**: Multiple paths call `Value::as_object().unwrap()` without guarding against malformed payloads. `RecordService::create_record` (`crates/core/src/records.rs:86`) and `CollectionService::validate_field_data` (`crates/core/src/collections.rs:526`) can panic, turning bad client input into a denial-of-service.
- **Insecure dynamic filtering**: `parse_filter_expression` builds SQL fragments via string interpolation (`crates/core/src/records.rs:459-475`), exposing the records API to SQL injection. Only a minimal `'` replacement is applied; numeric and boolean filters are unhandled.
- **Realtime broadcast broken**: The WebSocket handler instantiates a fresh `RealtimeManager` per connection (`crates/server/src/realtime.rs:389`), so CRUD hooks that emit through `state.realtime_manager` never reach clients. This is a functional bug that silently drops realtime events.
- **File metadata corruption**: File fields persist metadata by stringifying JSON (`crates/core/src/records.rs:408-410`). Retrieval later expects structured JSON (`crates/server/src/files.rs:372-389`), causing deserialisation failures and blocking downloads.
- **Blocking primitives in async context**: Rule evaluation uses `std::sync::Mutex` (`crates/server/src/routes.rs:692`), and the realtime manager relies on `std::sync::RwLock`. On a multi-core Tokio runtime these locks can stall whole worker threads.
- **Readiness probe gives false positives**: `check_database_health` and `check_storage_health` unconditionally return `true` (`crates/server/src/routes.rs:389-400`), undermining deployment health checks and potentially masking outages.
- **Debug logging leakage**: `SchemaManager::create_collection_with_table` logs raw SQL via `dbg!` (`crates/core/src/schema_manager.rs:37`), unintentionally exposing schema details in production logs.

## Additional Observations
- Rule engine cache is guarded by a `Mutex` without timeout; heavy rule evaluation could serialize requests.
- Large optional feature surface (`s3-storage`, `oauth2`, `image-transforms`) lacks integration tests; enabling them may surface hidden regressions.
- Audit logger is feature-rich but not wired into REST handlers yet, limiting its coverage.

## Recommendations
1. Validate payload shapes before dereferencing, returning structured errors rather than panicking.
2. Replace `parse_filter_expression` with parameterised query builders or precompiled statements per filter clause.
3. Reuse the `AppState` realtime manager inside `websocket_handler` and add regression tests to ensure events propagate.
4. Store file metadata as JSON (via `serde_json::to_string`) and hydrate on read to align with API expectations.
5. Swap blocking locks for `tokio::sync::Mutex/RwLock`, or restructure to avoid locking on the async hot path.
6. Implement actual health checks (database ping, storage exists check) and propagate failures through readiness endpoints.
7. Remove `dbg!` traces and rely on structured tracing with log levels tied to configuration.
