# Multi-stage build for RustBase
FROM rust:1.75-slim as builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Create app user
RUN useradd --create-home --shell /bin/bash app

WORKDIR /app

# Copy manifests
COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/
COPY src/ src/
COPY migrations/ migrations/

# Build dependencies (this is cached if Cargo.toml doesn't change)
RUN cargo build --release

# Runtime stage
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    curl \
    sqlite3 \
    && rm -rf /var/lib/apt/lists/*

# Create app user
RUN useradd --create-home --shell /bin/bash --uid 1000 app

# Create application directory
WORKDIR /app

# Copy binary from builder stage
COPY --from=builder /app/target/release/rustbase /usr/local/bin/rustbase

# Create data directories
RUN mkdir -p /app/data/storage && \
    chown -R app:app /app

# Copy admin UI files (if they exist)
COPY --chown=app:app crates/server/admin/ /app/admin/

# Switch to app user
USER app

# Create default configuration
RUN cat > /app/rustbase.toml << 'EOF'
[server]
host = "0.0.0.0"
port = 8090

[database]
url = "sqlite:data/rustbase.db"
auto_migrate = true

[auth]
jwt_secret = "change-this-in-production"
token_ttl = 900
refresh_ttl = 86400

[storage]
backend = "local"

[storage.local]
base_path = "data/storage"
max_file_size = 52428800

[features]
metrics = false
EOF

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8090/healthz || exit 1

# Expose port
EXPOSE 8090

# Set environment variables
ENV RUST_LOG=info
ENV RUSTBASE_SERVER_HOST=0.0.0.0
ENV RUSTBASE_SERVER_PORT=8090

# Start command
CMD ["rustbase", "serve"]