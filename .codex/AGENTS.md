# FerriteDB Senior Rust Agent Guide

## Mission & Mindset
- Act as the lead Rust engineer: design features, review architecture trade-offs, and land production-ready code without hand-holding.
- Keep FerriteDB reliable. Favor clarity, observability, and explicit error handling over clever tricks.
- Communicate assumptions. If information is missing, state it, propose a default, and move forward.

## Architecture Snapshot
- `src/main.rs`: CLI entrypoint that wires configuration, tracing, and subcommands (`serve`, `migrate`, `admin`, etc.).
- `crates/server`: Axum-based HTTP/WebSocket server. Key modules: `server.rs` (bootstrap), `routes.rs` (REST routing), `realtime.rs` (subscriptions), `files.rs` (file delivery), `config.rs` (runtime config), `openapi.rs` (Swagger generation).
- `crates/core`: Domain layer and persistence orchestration—collections, auth, seed data, repositories, audit logging, schema management; talks to SQLite via `sqlx`.
- `crates/storage`: Pluggable file backends (local + optional S3/image transforms) with a thin error surface.
- `crates/rules`: CEL-inspired rule engine powering access control expressions.
- `crates/sdk-rs`: Client SDK used by the admin UI and external consumers for typed access and realtime helpers.
- `migrations/`: SQL migrations; `.sqlx/` cache keeps prepared statement metadata for offline builds.

## Data Flow Essentials
1. CLI (`serve`) loads `ferritedb_core::CoreConfig`, builds storage + rule engines, and launches the Axum stack.
2. Requests hit `routes.rs`, which call into domain services in `crates/core` (repositories, auth, schema manager).
3. Persistence stays in `crates/core::repository` using `sqlx::query!` macros backed by the cached `.sqlx` data.
4. Realtime updates originate from repository events and propagate through `crates/server/src/realtime.rs` to connected WebSocket clients.
5. File operations are abstracted behind `ferritedb_storage::backend::*`, keeping HTTP handlers storage-agnostic.

## Design & Feature Workflow
- Clarify scope and API contract (REST, realtime, admin UI). Capture open questions before touching code.
- Model data changes in `crates/core` first. Update migrations + seed data if schema changes; refresh `.sqlx` metadata with `cargo sqlx prepare --workspace` after touching queries.
- Extend domain types (`models.rs`, `collections.rs`, `repository.rs`) before server wiring. Maintain separation: server = transport, core = business.
- Surface functionality in `crates/server`: add routes, handlers, validators, OpenAPI docs, and realtime hooks. Ensure access control rules exist.
- Update client touchpoints when needed (`crates/sdk-rs`, `crates/server/admin`). Align TypeScript bindings with Rust types when touching the admin UI.
- Document operational impacts (`OPERATIONS.md`, `ROADMAP.md`, config files) when behavior or setup shifts.

## Bug Fix & Hardening Loop
1. Reproduce with targeted tests (`cargo test <name>`, integration suites in `crates/server/tests`, or scripts in `scripts/`).
2. Instrument with `tracing` spans/logs instead of printlns. Verify error enums bubble up with context via `thiserror`/`anyhow`.
3. Patch the minimal surface but consider ripples across crates (server ↔ core ↔ storage).
4. Add or adjust tests close to the bug: unit tests in the crate, integration tests under `tests/`, or WebSocket cases in `crates/server/tests`.
5. Run the full check cadence (fmt, clippy, tests) before shipping.

## Coding Standards & Patterns
- Rust 2021, async via Tokio. Keep futures `Send` unless there's a compelling reason; annotate lifetimes consciously when sharing DB handles.
- Prefer small, composable modules with explicit inputs/outputs. Use newtypes or builder structs for complex parameter sets.
- Error handling: convert lower-level errors with `?` + `From`/`Into`, enrich context with `anyhow::Context` in CLI paths, and map to HTTP responses in `error.rs`.
- Configuration: surface everything through `CoreConfig`/`ServerConfig`; avoid hardcoding paths or feature flags.
- Concurrency: reuse `Arc` clones for shared state; ensure mutable data lives behind `Mutex`/`RwLock` only when unavoidable.
- Logging & metrics: emit structured `tracing` events (`info!`, `warn!`, `error!`) and hook into optional `metrics` feature when relevant.

## Quality Gates & Tooling
- Format: `cargo fmt`.
- Lint: `cargo clippy --workspace --all-targets -- -D warnings`.
- Tests: `cargo test --workspace`; run focused suites (e.g. `cargo test -p ferritedb-server realtime`).
- Optional extras: `just check-all` (fmt-check, lint, test, audit), `cargo tarpaulin` for coverage, `cargo audit` for dependency health.
- For admin UI tweaks, run the server (`cargo run -- serve`) and hot-reload frontend assets under `crates/server/admin` as needed.

## Operational Awareness
- Default config lives in `ferritedb.dev.toml`; ensure new knobs get doc entries and sensible defaults.
- Realtime features should degrade gracefully—validate subscription filters and push state transitions through typed events.
- When touching storage, respect both local and S3 variants; guard feature-gated code (`s3-storage`, `image-transforms`).
- Maintain migrations idempotence; use `migrations/<timestamp>_description.sql` and keep `seed.rs` aligned with new schemas.

## Delivery Checklist
- [ ] Requirements confirmed; assumptions documented.
- [ ] Domain, transport, and storage layers updated coherently.
- [ ] Tests updated/added; full suite green.
- [ ] fmt + clippy clean; security audit considered when dependencies change.
- [ ] Docs/configs updated so operators and SDK users are never surprised.

Stay pragmatic: prefer incremental, reviewable PRs, but do not hesitate to refactor when the payoff is clear. 