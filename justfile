# RustBase Development Tasks

# Default recipe to display help
default:
    @just --list

# Development server with hot reload
dev:
    cargo watch -x "run -- serve"

# Build the project
build:
    cargo build --release

# Run tests
test:
    cargo test

# Run tests with coverage
test-coverage:
    cargo tarpaulin --out html --output-dir coverage

# Run linting
lint:
    cargo clippy -- -D warnings

# Format code
fmt:
    cargo fmt

# Check formatting
fmt-check:
    cargo fmt -- --check

# Run security audit
audit:
    cargo audit

# Clean build artifacts
clean:
    cargo clean

# Generate documentation
docs:
    cargo doc --no-deps --open

# Run benchmarks
bench:
    cargo bench

# Initialize database and seed data
seed:
    cargo run -- seed

# Start server
serve:
    cargo run -- serve

# Run database migrations
migrate:
    cargo run -- migrate run

# Create admin user
admin-create email password:
    cargo run -- admin create --email {{email}} --password {{password}}

# List users
admin-list:
    cargo run -- admin list

# Generate JWT token
gen-jwt user:
    cargo run -- gen-jwt {{user}}

# Import data
import collection file:
    cargo run -- import {{collection}} {{file}}

# Export data
export collection:
    cargo run -- export {{collection}}

# Docker build
docker-build:
    docker build -t rustbase:latest .

# Docker run
docker-run:
    docker run -p 8090:8090 rustbase:latest

# Docker compose up
docker-up:
    docker-compose up -d

# Docker compose down
docker-down:
    docker-compose down

# Docker compose with monitoring
docker-up-monitoring:
    docker-compose --profile with-monitoring up -d

# Docker compose with PostgreSQL
docker-up-postgres:
    docker-compose --profile with-postgres up -d

# Docker compose logs
docker-logs:
    docker-compose logs -f rustbase

# Install development dependencies
install-deps:
    cargo install cargo-watch cargo-tarpaulin cargo-audit

# Setup development environment
setup: install-deps
    @echo "Development environment setup complete!"
    @echo "Run 'just dev' to start the development server"

# Release build with optimizations
release:
    cargo build --release
    strip target/release/rustbase

# Cross-compile for different targets
cross-compile target:
    cross build --release --target {{target}}

# Package release
package version:
    #!/usr/bin/env bash
    set -euo pipefail
    
    # Build for multiple targets
    targets=("x86_64-unknown-linux-gnu" "x86_64-apple-darwin" "aarch64-apple-darwin" "x86_64-pc-windows-gnu")
    
    mkdir -p dist
    
    for target in "${targets[@]}"; do
        echo "Building for $target..."
        cross build --release --target $target
        
        # Create archive
        if [[ $target == *"windows"* ]]; then
            zip -j "dist/rustbase-{{version}}-$target.zip" "target/$target/release/rustbase.exe"
        else
            tar -czf "dist/rustbase-{{version}}-$target.tar.gz" -C "target/$target/release" rustbase
        fi
    done
    
    echo "Release packages created in dist/"

# Run integration tests
test-integration:
    cargo test --test integration_tests

# Run security tests
test-security:
    cargo test --test security_tests

# Run performance tests
test-performance:
    cargo test --release --test performance_tests

# Check all (format, lint, test, audit)
check-all: fmt-check lint test audit
    @echo "All checks passed!"

# Pre-commit hook
pre-commit: fmt lint test
    @echo "Pre-commit checks passed!"

# CI pipeline simulation
ci: fmt-check lint test audit
    @echo "CI pipeline simulation completed!"

# Load test with wrk (requires wrk to be installed)
load-test:
    wrk -t12 -c400 -d30s http://localhost:8090/healthz

# Database backup
backup:
    #!/usr/bin/env bash
    timestamp=$(date +%Y%m%d_%H%M%S)
    mkdir -p backups
    cp data/rustbase.db "backups/rustbase_backup_$timestamp.db"
    echo "Backup created: backups/rustbase_backup_$timestamp.db"

# Database restore
restore backup_file:
    cp {{backup_file}} data/rustbase.db
    @echo "Database restored from {{backup_file}}"

# Generate OpenAPI spec
openapi-spec:
    curl -s http://localhost:8090/api/openapi.json | jq . > openapi.json
    @echo "OpenAPI spec saved to openapi.json"

# Start development environment with all services
dev-full:
    docker-compose --profile with-monitoring --profile with-postgres up -d
    @echo "Full development environment started!"
    @echo "RustBase: http://localhost:8090"
    @echo "Grafana: http://localhost:3000 (admin/admin)"
    @echo "Prometheus: http://localhost:9090"

# Stop development environment
dev-stop:
    docker-compose down

# View application logs
logs:
    tail -f /var/log/rustbase/rustbase.log

# Monitor system resources
monitor:
    watch -n 1 'ps aux | grep rustbase; echo ""; df -h; echo ""; free -h'

# Update dependencies
update-deps:
    cargo update
    cargo audit

# Security scan with cargo-deny
security-scan:
    cargo deny check

# Generate changelog
changelog:
    git cliff --output CHANGELOG.md

# Tag release
tag-release version:
    git tag -a v{{version}} -m "Release v{{version}}"
    git push origin v{{version}}

# Publish to crates.io (dry run)
publish-dry:
    cargo publish --dry-run

# Publish to crates.io
publish:
    cargo publish