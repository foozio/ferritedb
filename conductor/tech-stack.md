# Tech Stack: FerriteDB

## Core Backend
- **Programming Language:** Rust (Edition 2021)
- **Web Framework:** Axum (v0.7)
- **Async Runtime:** Tokio (v1.35)
- **Error Handling:** Anyhow, Thiserror

## Data Persistence
- **Primary Database:** SQLite (v3)
- **Database Driver/ORM:** SQLx (v0.7) with asynchronous support and compile-time query validation.

## API & Communication
- **API Style:** REST (OpenAPI/Swagger auto-generated)
- **Realtime:** WebSockets (Axum/Tokio-tungstenite)
- **Serialization:** Serde, Serde_json

## Security & Auth
- **Password Hashing:** Argon2
- **Authentication:** JSON Web Tokens (JWT)
- **Access Control:** CEL-like expressions (via Pest parser)

## Storage & Assets
- **Local Storage:** Local filesystem integration.
- **Cloud Storage:** S3-compatible backend (via AWS SDK for Rust).

## Infrastructure & Tooling
- **Configuration:** Figment (supporting TOML, JSON, and Env variables).
- **CLI:** Clap (v4.4).
- **Observability:** Tracing, Tracing-subscriber.
- **Testing:** Rust built-in test runner, Tempfile for integration testing.
