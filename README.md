# FerriteDB

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/rust-1.75+-orange.svg)](https://www.rust-lang.org)


**FerriteDB** is a developer-friendly backend service that provides a complete backend-as-a-service solution in a single self-contained binary. Built with Rust for performance, security, and reliability.

## ✨ Features

- **🚀 Single Binary Deployment** - Everything you need in one executable
- **📊 Dynamic Collections** - Define data schemas without writing SQL
- **🔐 Built-in Authentication** - JWT-based auth with Argon2 password hashing
- **🛡️ Rule-based Access Control** - Fine-grained permissions with CEL-like expressions
- **📡 Realtime Updates** - WebSocket subscriptions for live data
- **📁 File Storage** - Local and S3-compatible storage backends
- **🌐 REST APIs** - Automatic API generation for all collections
- **👨‍💻 Admin Interface** - Web-based management dashboard
- **📖 API Documentation** - Auto-generated OpenAPI specs with Swagger UI
- **🔧 CLI Tools** - Complete command-line interface for management

## 🚀 Quick Start

### Installation

Download the latest release for your platform:

```bash
# macOS (Apple Silicon)
curl -L https://github.com/ferritedb/ferritedb/releases/latest/download/ferritedb-macos-arm64 -o ferritedb
chmod +x ferritedb

# macOS (Intel)
curl -L https://github.com/ferritedb/ferritedb/releases/latest/download/ferritedb-macos-x64 -o ferritedb
chmod +x ferritedb

# Linux (x64)
curl -L https://github.com/ferritedb/ferritedb/releases/latest/download/ferritedb-linux-x64 -o ferritedb
chmod +x ferritedb

# Windows
# Download ferritedb-windows-x64.exe from releases page
```

Or build from source:

```bash
git clone https://github.com/ferritedb/ferritedb.git
cd ferritedb
cargo build --release
```

### Start the Server

```bash
# Initialize example collections and seed data
./ferritedb seed

# Start the server
./ferritedb serve
```

That's it! FerriteDB is now running on `http://localhost:8090`

### Access Points

- **Admin Interface**: http://localhost:8090/admin
- **API Documentation**: http://localhost:8090/docs
- **Health Check**: http://localhost:8090/healthz
- **REST API**: http://localhost:8090/api/

### Default Credentials

The seed command creates demo users:

- **Admin**: `admin@ferritedb.dev` / `admin123`
- **Users**: `alice@example.com`, `bob@example.com`, `carol@example.com` / `password123`

## 📚 Documentation

### Creating Collections

Collections are dynamic schemas that define your data structure:

```bash
# Using the CLI
ferritedb admin create-collection posts \
  --field title:text:required \
  --field content:text \
  --field published:boolean:default=false \
  --field author_id:relation:users

# Or use the Admin UI at /admin
```

### Access Rules

Define who can access your data with CEL-like expressions:

```javascript
// List Rule: Anyone can see published posts
"record.published = true || @request.auth.id != ''"

// View Rule: Anyone can view published, owners can view drafts
"record.published = true || record.author_id = @request.auth.id"

// Create Rule: Only authenticated users
"@request.auth.id != ''"

// Update Rule: Only the author or admin
"record.author_id = @request.auth.id || @request.auth.role = 'admin'"

// Delete Rule: Only admins
"@request.auth.role = 'admin'"
```

### REST API Usage

```bash
# Login
curl -X POST http://localhost:8090/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "alice@example.com", "password": "password123"}'

# Create a post
curl -X POST http://localhost:8090/api/collections/posts/records \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"title": "Hello World", "content": "My first post!", "published": true}'

# List posts
curl http://localhost:8090/api/collections/posts/records

# Get specific post
curl http://localhost:8090/api/collections/posts/records/POST_ID

# Update post
curl -X PATCH http://localhost:8090/api/collections/posts/records/POST_ID \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"title": "Updated Title"}'
```

### Realtime Subscriptions

```javascript
const ws = new WebSocket('ws://localhost:8090/realtime');

ws.onopen = () => {
  // Subscribe to posts collection
  ws.send(JSON.stringify({
    type: 'subscribe',
    collection: 'posts',
    filter: 'record.published = true'
  }));
};

ws.onmessage = (event) => {
  const data = JSON.parse(event.data);
  console.log('Realtime update:', data);
};
```

### File Uploads

```bash
# Upload file to a record
curl -X POST http://localhost:8090/api/files/posts/POST_ID/featured_image \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -F "file=@image.jpg"

# Download file
curl http://localhost:8090/api/files/posts/POST_ID/featured_image
```

## 🔧 Configuration

FerriteDB can be configured via environment variables, config files, or CLI arguments:

### Environment Variables

```bash
export FERRITEDB_SERVER_HOST=0.0.0.0
export FERRITEDB_SERVER_PORT=8090
export FERRITEDB_DATABASE_URL=sqlite:data/ferritedb.db
export FERRITEDB_AUTH_JWT_SECRET=your-secret-key
export FERRITEDB_STORAGE_BACKEND=local
export FERRITEDB_STORAGE_LOCAL_BASE_PATH=data/storage
```

### Configuration File

Create `ferritedb.toml`:

```toml
[server]
host = "0.0.0.0"
port = 8090
cors_origins = ["*"]

[server.rate_limit]
requests_per_minute = 60
burst_size = 10

[database]
url = "sqlite:data/ferritedb.db"
max_connections = 10
connection_timeout = 30
auto_migrate = true

[auth]
jwt_secret = "your-secret-key-change-in-production"
token_ttl = 900  # 15 minutes
refresh_ttl = 86400  # 24 hours
password_min_length = 8

[storage]
backend = "local"

[storage.local]
base_path = "data/storage"
max_file_size = 52428800  # 50MB

# Optional S3 configuration
# [storage.s3]
# bucket = "ferritedb-files"
# region = "us-east-1"
# access_key_id = "your-access-key"
# secret_access_key = "your-secret-key"

[features]
multi_tenant = false
full_text_search = false
metrics = false
```

## 🛠️ CLI Commands

### Server Management

```bash
# Start server
ferritedb serve --host 0.0.0.0 --port 8090

# Database migrations
ferritedb migrate run
ferritedb migrate status

# Initialize examples
ferritedb seed
```

### User Management

```bash
# Create admin user
ferritedb admin create --email admin@example.com

# List users
ferritedb admin list

# Delete user
ferritedb admin delete user@example.com
```

### Data Management

```bash
# Import data
ferritedb import posts data.json
ferritedb import users users.csv

# Export data
ferritedb export posts --output posts_backup.json

# Generate JWT for testing
ferritedb gen-jwt alice@example.com --expires 3600
```

## 🏗️ Architecture

FerriteDB is built with a modular architecture:

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Admin UI      │    │   REST API      │    │   WebSocket     │
│   (Static)      │    │   (Axum)        │    │   (Realtime)    │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         └───────────────────────┼───────────────────────┘
                                 │
         ┌─────────────────────────────────────────────────────┐
         │              Core Engine                            │
         │  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐   │
         │  │Collections  │ │    Auth     │ │   Rules     │   │
         │  │   Service   │ │   Service   │ │   Engine    │   │
         │  └─────────────┘ └─────────────┘ └─────────────┘   │
         └─────────────────────────────────────────────────────┘
                                 │
         ┌─────────────────────────────────────────────────────┐
         │              Data Layer                             │
         │  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐   │
         │  │   SQLite    │ │File Storage │ │   Schema    │   │
         │  │  Database   │ │(Local/S3)   │ │  Manager    │   │
         │  └─────────────┘ └─────────────┘ └─────────────┘   │
         └─────────────────────────────────────────────────────┘
```

### Key Components

- **Core Engine**: Business logic, collections, authentication, and rules
- **REST API**: Axum-based HTTP server with middleware
- **Realtime**: WebSocket server for live updates
- **Admin UI**: Web-based management interface
- **CLI**: Command-line tools for administration
- **Storage**: Pluggable file storage (local/S3)
- **Database**: SQLite with dynamic schema management

## 🔒 Security

FerriteDB implements security best practices:

- **Password Hashing**: Argon2id with secure parameters
- **JWT Tokens**: Short-lived access tokens with refresh rotation
- **Input Validation**: Comprehensive validation and sanitization
- **SQL Injection Prevention**: Parameterized queries
- **CORS Protection**: Configurable cross-origin policies
- **Rate Limiting**: Configurable request throttling
- **PII Redaction**: Automatic sensitive data masking in logs
- **CSRF Protection**: Cross-site request forgery prevention
- **Audit Logging**: Complete audit trail for admin actions

## 🚀 Deployment

### Docker

```dockerfile
FROM ferritedb/ferritedb:latest

# Copy configuration
COPY ferritedb.toml /app/ferritedb.toml

# Expose port
EXPOSE 8090

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:8090/healthz || exit 1

# Start server
CMD ["ferritedb", "serve"]
```

### Docker Compose

```yaml
version: '3.8'

services:
  ferritedb:
    image: ferritedb/ferritedb:latest
    ports:
      - "8090:8090"
    volumes:
      - ./data:/app/data
      - ./ferritedb.toml:/app/ferritedb.toml
    environment:
      - FERRITEDB_AUTH_JWT_SECRET=your-production-secret
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8090/healthz"]
      interval: 30s
      timeout: 10s
      retries: 3
    restart: unless-stopped

  # Optional: Reverse proxy
  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf
      - ./ssl:/etc/nginx/ssl
    depends_on:
      - ferritedb
    restart: unless-stopped
```

### Cloud Deployment

#### Railway

```bash
# Install Railway CLI
npm install -g @railway/cli

# Deploy
railway login
railway init
railway up
```

#### Fly.io

```bash
# Install Fly CLI
curl -L https://fly.io/install.sh | sh

# Deploy
fly launch
fly deploy
```

#### DigitalOcean App Platform

```yaml
name: ferritedb
services:
- name: api
  source_dir: /
  github:
    repo: your-username/your-ferritedb-fork
    branch: main
  run_command: ferritedb serve
  environment_slug: rust
  instance_count: 1
  instance_size_slug: basic-xxs
  envs:
  - key: FERRITEDB_AUTH_JWT_SECRET
    value: your-production-secret
    type: SECRET
  http_port: 8090
  health_check:
    http_path: /healthz
```

## 🧪 Development

### Prerequisites

- Rust 1.75+
- SQLite 3.35+

### Setup

```bash
# Clone repository
git clone https://github.com/ferritedb/ferritedb.git
cd ferritedb

# Install dependencies
cargo build

# Run tests
cargo test

# Start development server
cargo run -- serve

# Run with debug logging
RUST_LOG=debug cargo run -- serve
```

### Project Structure

```
ferritedb/
├── crates/
│   ├── core/           # Core business logic
│   ├── server/         # HTTP server and routes
│   ├── storage/        # File storage backends
│   ├── rules/          # Rules engine
│   └── sdk-rs/         # Rust client SDK
├── admin/              # Admin UI (static files)
├── migrations/         # Database migrations
├── examples/           # Usage examples
├── docs/               # Documentation
└── src/                # CLI application
```

### Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/amazing-feature`
3. Make your changes
4. Add tests for new functionality
5. Run tests: `cargo test`
6. Run linting: `cargo clippy`
7. Format code: `cargo fmt`
8. Commit changes: `git commit -m 'Add amazing feature'`
9. Push to branch: `git push origin feature/amazing-feature`
10. Open a Pull Request

### Development Commands

```bash
# Run all tests
just test

# Run with hot reload
just dev

# Lint code
just lint

# Format code
just fmt

# Build release
just build

# Generate documentation
just docs
```

## 📊 Performance

FerriteDB is designed for performance:

- **Memory Usage**: ~10MB base memory footprint
- **Startup Time**: <100ms cold start
- **Request Latency**: <1ms for simple queries
- **Throughput**: 10,000+ requests/second on modern hardware
- **Database**: SQLite with WAL mode for concurrent reads
- **Caching**: In-memory schema and rule caching

### Benchmarks

```bash
# Run performance tests
cargo bench

# Load testing with wrk
wrk -t12 -c400 -d30s http://localhost:8090/api/collections/posts/records
```

## 🤝 Community

- **GitHub**: [github.com/ferritedb/ferritedb](https://github.com/ferritedb/ferritedb)
- **Discord**: [discord.gg/ferritedb](https://discord.gg/ferritedb)
- **Discussions**: [GitHub Discussions](https://github.com/ferritedb/ferritedb/discussions)
- **Issues**: [GitHub Issues](https://github.com/ferritedb/ferritedb/issues)

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [PocketBase](https://pocketbase.io/) - Inspiration for the project
- [Supabase](https://supabase.com/) - Backend-as-a-Service concepts
- [Rust Community](https://www.rust-lang.org/community) - Amazing ecosystem and support

## 🗺️ Roadmap

- [ ] **v1.1**: Multi-tenancy support
- [ ] **v1.2**: Full-text search with FTS5
- [ ] **v1.3**: GraphQL API support
- [ ] **v1.4**: Plugin system
- [ ] **v1.5**: Distributed deployment
- [ ] **v2.0**: PostgreSQL backend support

---

**Built with ❤️ in Rust**

For more information, visit our [documentation](https://ferritedb.dev/docs) or join our [community](https://discord.gg/ferritedb).