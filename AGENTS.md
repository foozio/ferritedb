# Repository Guidelines

## Project Structure & Module Organization
FerriteDB is anchored by `src/main.rs`, which wires the runtime and launches the service. Domain modules live under `crates/`: `crates/core` hosts business logic, `crates/server` exposes Axum routes and middleware, `crates/storage` provides pluggable backends, `crates/rules` evaluates access policies, and `crates/sdk-rs` contains the Rust client. Integration artifacts sit in `tests/`, while database migrations reside in `migrations/`. Operational assets are kept in `scripts/`, packaging recipes in `release/`, and longer-form docs under `docs/`.

## Build, Test, and Development Commands
Use `just dev` for hot-reload development (`cargo watch -x "run -- serve"`). `just build` produces an optimized binary, and `just serve` runs the server once. `just test`, `just test-integration`, and `just test-performance` cover unit, integration, and performance suites. Quality gates include `just lint` (Clippy), `just fmt` (rustfmt), and `just test-coverage` (Tarpaulin HTML in `coverage/`).

## Coding Style & Naming Conventions
Stick to the default Rust 4-space, rustfmt-managed style; run `just fmt` before submitting. Use single-responsibility modules, prefer early returns over deep nesting, and document non-obvious invariants inline. Name modules and files with `snake_case`, types with `CamelCase`, and constants with `SCREAMING_SNAKE_CASE`. Clippy settings in `clippy.toml` tighten complexity thresholds, so `just lint` must pass cleanly.

## Testing Guidelines
Unit tests live next to their modules; integration suites reside in `tests/` and `crates/server/tests/`. Name integration test files after the feature under test (e.g., `auth_tests.rs`). Always run `just test`; include `just test-integration` when touching endpoints or migrations, and `just test-performance` for performance-critical paths. Verify new code preserves coverage before sharing results from `just test-coverage`.

## Commit & Pull Request Guidelines
Commits should be focused and written in the imperative mood (e.g., `Mask password in URI logs`). Reference impacted crates or services when useful. Pull requests need a concise summary, observable impact, and evidence of the commands you ran. Link issues or roadmap items, attach screenshots for admin UI updates, and mention rollout or migration steps whenever schema files in `migrations/` change.

## Security & Configuration Notes
Do not commit secrets; keep overrides in `.env` or `ferritedb.dev.toml`. Run `just audit` and `just security-scan` after dependency upgrades or auth changes. For new endpoints, document required scopes in `docs/` and ensure corresponding migrations are reversible before opening a pull request.
