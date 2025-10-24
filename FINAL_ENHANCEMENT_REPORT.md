# Final Enhancement Report

## Architecture Synopsis
- **Binary (`src/main.rs`)** – Clap-driven CLI that loads `CoreConfig` via Figment, orchestrates subcommands (serve, migrate, admin, import/export, seed) and boots the HTTP server on Tokio.
- **Core crate (`crates/core`)** – Domain hub for configuration, authentication, schema metadata, dynamic record management, auditing, PII scrubbing, seeding, and SQLite access through SQLx. `CollectionService`+`SchemaManager` generate per-collection tables; `RecordService` performs CRUD with runtime schema validation.
- **Server crate (`crates/server`)** – Axum-based API layer exposing auth, collection, record, and file routes. Middleware stack applies tracing, rate limiting, security headers, CSRF helpers, and validation. WebSocket realtime module multiplexes subscriptions and broadcasts CRUD events.
- **Storage crate (`crates/storage`)** – Abstracts file persistence (`StorageBackend`) with secure local implementation and optional S3 adapter.
- **Rules crate (`crates/rules`)** – CEL-like parser, AST cache, and evaluator powering access rules and realtime filters.
- **SDK (`crates/sdk-rs`)** – Async client wrapper for REST and realtime APIs (reqwest + tokio-tungstenite), currently thin but structured for expansion.

Primary dependencies include Tokio (async runtime), Axum/Tower (HTTP stack), SQLx (SQLite driver), Argon2/JWT (auth), Pest (rule parsing), and serde/schemars for (de)serialization and schema generation. The runtime flow: CLI loads config → `Server::new` initialises Database/Auth/Repositories/Storage → `AppState` injects services into routes → requests hit middleware → handlers call `CollectionService`/`RecordService`/`RuleEngine` and optionally broadcast via `RealtimeManager`.

## Key Issues & Risks
- Panics on malformed record payloads via `Value::as_object().unwrap()` (`crates/core/src/records.rs:86`, `crates/core/src/collections.rs:526`), enabling DoS.
- SQL injection window from naive string interpolation in `parse_filter_expression` (`crates/core/src/records.rs:459-475`).
- WebSocket events never reach clients because `websocket_handler` creates a new `RealtimeManager` (`crates/server/src/realtime.rs:389`) instead of reusing the shared instance used by CRUD hooks.
- File metadata serialisation mismatch (`crates/core/src/records.rs:408-410` vs. `crates/server/src/files.rs:372-389`) breaks download flows.
- Blocking `std::sync` locks guard hot paths (`crates/server/src/routes.rs:692`) and the realtime registry, risking thread starvation under load.
- Readiness probes return green regardless of backend health (`crates/server/src/routes.rs:389-400`), masking outages.
- `SchemaManager::create_collection_with_table` leaks SQL via `dbg!` (`crates/core/src/schema_manager.rs:37`).

## Recommended Enhancements
1. Harden data handling: guard JSON structures, return validation errors, and enforce typed filter parsing with parameterised SQL.
2. Repair realtime delivery by injecting `state.realtime_manager.clone()` into `websocket_handler` and covering broadcast paths with integration tests.
3. Align file metadata storage/reads (store canonical JSON, hydrate to `FileMetadata`) and add regression tests covering upload → serve.
4. Introduce async-friendly synchronization primitives and reduce critical-section scope in rule evaluation and realtime subsystems.
5. Implement real health checks (SQL ping, storage `.exists`) and expose metrics via the optional `metrics` feature.
6. Tighten ops polish: remove debug traces, expand audit logging coverage, and document feature-gated pathways (OAuth2, S3, image transforms) with smoke tests.
