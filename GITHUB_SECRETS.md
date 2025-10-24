# GitHub Secrets Reference

Use these secrets to configure CI pipelines, release automation, or deployment workflows for FerriteDB. Scope each secret to the minimum set of environments (forks, PR workflows, production deploys).

## Core Runtime
- `FERRITEDB_AUTH_JWT_SECRET` – HS256 signing key for JWT access/refresh tokens. Generate a 256-bit random string; rotate regularly.
- `DATABASE_URL` – SQLite path for simple workflows or a DSN for external targets when adapters are introduced (e.g., `sqlite://data/ferritedb.db`).
- `RUST_LOG` (optional) – desired tracing level during integration workflows (`info`, `debug`).

## Storage Backends
- `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` – required when enabling the `s3-storage` feature; grant least-privilege access to the target bucket.
- `AWS_REGION` – AWS region for the S3 client (e.g., `us-east-1`).
- `FERRITEDB_S3_BUCKET` – bucket name used by the storage layer.
- `FERRITEDB_S3_ENDPOINT` (optional) – set for S3-compatible providers (MinIO, Cloudflare R2).

## OAuth & External Auth (feature gated)
- `OAUTH_CLIENT_ID` / `OAUTH_CLIENT_SECRET` – credentials for enabled OAuth2 providers.
- `OAUTH_REDIRECT_URI` – callback URL registered with the provider.

## Release & Packaging
- `CARGO_REGISTRY_TOKEN` – crates.io API token for `just publish` / `cargo publish`.
- `GITHUB_TOKEN` – provided automatically in GitHub Actions; ensure permissions cover releases and tags for `just tag-release`.
- `DOCKERHUB_USERNAME` / `DOCKERHUB_TOKEN` – publish Docker images referenced by `just docker-build` and `just docker-up`.

## Observability & Security
- `SENTRY_DSN` or equivalent observability secret if error reporting is introduced.
- `SLACK_WEBHOOK_URL` or notification tokens to broadcast deploy/test results.
- `GITHUB_APP_PRIVATE_KEY` (optional) for automation bots interacting with issues/PRs.

### Management Tips
- Use environment-specific prefixes (`PROD_`, `STAGING_`) when multiple environments are driven via Actions matrices.
- Pair secrets with configuration files (`ferritedb.dev.toml`) committed to the repo to keep runtime settings reproducible while keeping credentials private.
- Rotate any credential consumed by the audit logger (`records_seed`, admin accounts) since the seed data is public and intended only for local development.
