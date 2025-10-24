# FerriteDB Product Requirements

## 1. Overview
FerriteDB delivers a backend-as-a-service packaged as a single Rust binary. It combines dynamic collection management, authentication, file storage, rule-based access control, and realtime updates so small teams can prototype and ship secure data APIs without standing up bespoke infrastructure.

## 2. Goals & Non-Goals
- Provide an opinionated backend that is installable via CLI, Docker, or Homebrew.
- Allow teams to design collections, fields, and access rules at runtime without writing SQL.
- Offer secure user authentication, audit logging, and WebSocket-driven realtime events out of the box.
- Non-goal: build a full visual builder or replace dedicated analytics/BI tooling.

## 3. Personas
- **Indie Developers / Startups** – need a plug-and-play backend with minimal ops work.
- **Platform Engineers** – embed FerriteDB as a tenant backend within a wider product.
- **Internal Tools Teams** – rapidly prototype data-centric applications for internal users.

## 4. Functional Requirements
- CLI must expose `serve`, `migrate`, `admin`, `import/export`, `gen-jwt`, and `seed` commands with consistent logging and error handling.
- HTTP API (Axum-based) must support authentication (`/api/auth/*`), collection CRUD, dynamic record CRUD with filtering, file uploads/downloads, and WebSocket subscriptions (`/realtime`).
- Core services must maintain collection schemas, generate per-collection SQLite tables, enforce field constraints, and run rules through the embedded rule engine.
- Storage layer must default to local disk with optional S3-compatible support and validate file metadata before persistence.
- Seed routines must initialize canonical `users` and `posts` collections, demo users, and sample content for onboarding.
- Admin UI assets and OpenAPI spec must be served from the same binary.

## 5. Non-Functional Requirements
- Target Rust 1.75+, SQLite 3.35+, and async Tokio runtime; support macOS/Linux/Windows via cross-compilation.
- Ensure auth paths use Argon2id hashing, JWT signing with HS256, and configurable token TTLs.
- Expose observability hooks: structured tracing, configurable rate limiting, readiness/health endpoints, and audit logging.
- Support extension via Cargo features (`oauth2`, `s3-storage`, `image-transforms`, `metrics`).
- Favor zero-copy data paths and structured error propagation (`anyhow`/`thiserror`) to keep latency under 100 ms for common CRUD operations on commodity hardware.

## 6. Success Metrics
- Server boots and handles CRUD requests under 2 seconds cold start on developer laptops.
- ≥90 % test coverage on core schema/record services, auth flows, and CLI happy paths.
- Ability to create ≥5 collections with 50+ fields each without manual migrations or errors.
- WebSocket updates delivered to subscribed clients within 500 ms of write completion.

## 7. Constraints & Assumptions
- SQLite is the default persistence layer; advanced users may swap via future adapters.
- Deployments rely on environment variables or `ferritedb.dev.toml` for configuration.
- CI/CD expects cargo-based workflows and optional Docker builds defined in `justfile`.

## 8. Open Questions
- Should collection rules support a richer expression language or standardized CEL subset?
- How should multi-tenant isolation be modeled in SQLite-backed deployments?
- What SLAs and retention rules should apply to audit logs and stored files?
