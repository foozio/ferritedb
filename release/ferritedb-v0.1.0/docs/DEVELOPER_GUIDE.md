# FerriteDB Developer Guide

This comprehensive guide covers everything you need to know to contribute to FerriteDB development, from setting up your development environment to understanding the codebase architecture.

## Table of Contents

- [Getting Started](#getting-started)
- [Development Environment](#development-environment)
- [Project Structure](#project-structure)
- [Building and Testing](#building-and-testing)
- [Contributing Guidelines](#contributing-guidelines)
- [Code Style and Standards](#code-style-and-standards)
- [Architecture Deep Dive](#architecture-deep-dive)
- [Adding New Features](#adding-new-features)
- [Debugging and Profiling](#debugging-and-profiling)
- [Release Process](#release-process)

## Getting Started

### Prerequisites

**Required:**
- Rust 1.75 or later
- Git
- A code editor (VS Code, IntelliJ IDEA, or Vim)

**Optional but Recommended:**
- Docker and Docker Compose
- PostgreSQL (for testing)
- Node.js (for frontend development)

### Quick Setup

```bash
# Clone the repository
git clone https://github.com/ferritedb/ferritedb.git
cd ferritedb

# Install Rust if you haven't already
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env

# Install required components
rustup component add clippy rustfmt

# Build the project
cargo build

# Run tests
cargo test

# Start development server
cargo run -- serve --config examples/dev.toml
```

## Development Environment

### Rust Setup

```bash
# Install latest stable Rust
rustup install stable
rustup default stable

# Install development tools
rustup component add clippy rustfmt rust-analyzer

# Install cargo extensions
cargo install cargo-watch cargo-expand cargo-audit
```

### IDE Configuration

#### VS Code Setup

Install recommended extensions:
```json
{
  "recommendations": [
    "rust-lang.rust-analyzer",
    "vadimcn.vscode-lldb",
    "serayuzgur.crates",
    "tamasfe.even-better-toml"
  ]
}
```

Create `.vscode/settings.json`:
```json
{
  "rust-analyzer.cargo.features": "all",
  "rust-analyzer.checkOnSave.command": "clippy",
  "editor.formatOnSave": true,
  "[rust]": {
    "editor.defaultFormatter": "rust-lang.rust-analyzer"
  }
}
```

#### IntelliJ IDEA Setup

1. Install the Rust plugin
2. Configure Rust toolchain in Settings → Languages & Frameworks → Rust
3. Enable Clippy integration
4. Set up run configurations for development

### Environment Variables

Create a `.env` file for development:
```bash
# Development configuration
RUST_LOG=ferritedb=debug,tower_http=debug
FERRITEDB_DATABASE_URL=sqlite:data/dev.db
FERRITEDB_AUTH_JWT_SECRET=dev-secret-change-in-production
FERRITEDB_STORAGE_BACKEND=local
FERRITEDB_STORAGE_LOCAL_PATH=data/storage
FERRITEDB_FEATURES_ADMIN_UI=true
FERRITEDB_FEATURES_METRICS=true
```

## Project Structure

```
ferritedb/
├── crates/                    # Rust workspace crates
│   ├── core/                  # Core business logic
│   │   ├── src/
│   │   │   ├── auth/          # Authentication system
│   │   │   ├── collections/   # Collection management
│   │   │   ├── records/       # Record operations
│   │   │   ├── rules/         # Rules engine
│   │   │   └── lib.rs
│   │   └── Cargo.toml
│   ├── server/                # HTTP server and API
│   │   ├── src/
│   │   │   ├── handlers/      # HTTP request handlers
│   │   │   ├── middleware/    # Custom middleware
│   │   │   ├── realtime/      # WebSocket handling
│   │   │   └── main.rs
│   │   └── Cargo.toml
│   ├── storage/               # File storage backends
│   │   ├── src/
│   │   │   ├── local/         # Local filesystem storage
│   │   │   ├── s3/            # S3-compatible storage
│   │   │   └── lib.rs
│   │   └── Cargo.toml
│   └── sdk-rs/                # Rust SDK
├── docs/                      # Documentation
├── examples/                  # Example configurations
├── tests/                     # Integration tests
├── scripts/                   # Build and deployment scripts
├── docker/                    # Docker configurations
├── .github/                   # GitHub workflows
├── Cargo.toml                 # Workspace configuration
├── Cargo.lock
└── README.md
```

### Crate Responsibilities

#### `ferritedb-core`
- **Purpose**: Core business logic and domain models
- **Key Components**:
  - Authentication and authorization
  - Collection schema management
  - Record validation and operations
  - Rules engine implementation
  - Database abstractions

#### `ferritedb-server`
- **Purpose**: HTTP server and API endpoints
- **Key Components**:
  - Axum web server setup
  - REST API handlers
  - WebSocket real-time functionality
  - Middleware (auth, CORS, rate limiting)
  - Admin UI serving

#### `ferritedb-storage`
- **Purpose**: File storage backends
- **Key Components**:
  - Storage trait definitions
  - Local filesystem implementation
  - S3-compatible storage
  - File metadata management

#### `ferritedb-sdk-rs`
- **Purpose**: Rust client SDK
- **Key Components**:
  - HTTP client wrapper
  - Type-safe API bindings
  - Authentication handling
  - Real-time subscriptions

## Building and Testing

### Development Workflow

```bash
# Watch for changes and rebuild
cargo watch -x "run -- serve --config examples/dev.toml"

# Run specific tests
cargo test auth::tests::test_login

# Run tests with output
cargo test -- --nocapture

# Run clippy for linting
cargo clippy -- -D warnings

# Format code
cargo fmt

# Check for security vulnerabilities
cargo audit
```

### Testing Strategy

#### Unit Tests
```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_user_creation() {
        let auth_service = AuthService::new(mock_db()).await;
        
        let user = auth_service.create_user(CreateUserRequest {
            email: "test@example.com".to_string(),
            password: "securepassword".to_string(),
        }).await.unwrap();
        
        assert_eq!(user.email, "test@example.com");
        assert!(user.verified);
    }
}
```

#### Integration Tests
```rust
// tests/integration/auth.rs
use ferritedb_server::test_utils::TestApp;

#[tokio::test]
async fn test_auth_flow() {
    let app = TestApp::new().await;
    
    // Register user
    let response = app.post("/api/auth/register")
        .json(&serde_json::json!({
            "email": "test@example.com",
            "password": "securepassword"
        }))
        .send()
        .await;
    
    assert_eq!(response.status(), 201);
    
    // Login
    let response = app.post("/api/auth/login")
        .json(&serde_json::json!({
            "email": "test@example.com",
            "password": "securepassword"
        }))
        .send()
        .await;
    
    assert_eq!(response.status(), 200);
    let body: serde_json::Value = response.json().await;
    assert!(body["token"].is_string());
}
```

#### Performance Tests
```rust
#[tokio::test]
async fn benchmark_record_creation() {
    let app = TestApp::new().await;
    let start = std::time::Instant::now();
    
    for i in 0..1000 {
        app.post("/api/collections/posts/records")
            .json(&serde_json::json!({
                "title": format!("Post {}", i),
                "content": "Test content"
            }))
            .send()
            .await;
    }
    
    let duration = start.elapsed();
    println!("Created 1000 records in {:?}", duration);
    assert!(duration.as_secs() < 10); // Should complete in under 10 seconds
}
```

### Test Utilities

```rust
// src/test_utils.rs
pub struct TestApp {
    pub client: reqwest::Client,
    pub base_url: String,
    pub db: Database,
}

impl TestApp {
    pub async fn new() -> Self {
        let db = Database::new_in_memory().await;
        let server = create_test_server(db.clone()).await;
        let base_url = format!("http://127.0.0.1:{}", server.port());
        
        Self {
            client: reqwest::Client::new(),
            base_url,
            db,
        }
    }
    
    pub fn post(&self, path: &str) -> RequestBuilder {
        self.client.post(&format!("{}{}", self.base_url, path))
    }
    
    pub async fn authenticate_as_admin(&self) -> String {
        // Create admin user and return JWT token
        todo!()
    }
}
```

## Contributing Guidelines

### Contribution Process

1. **Fork the Repository**
   ```bash
   git clone https://github.com/your-username/ferritedb.git
   cd ferritedb
   git remote add upstream https://github.com/ferritedb/ferritedb.git
   ```

2. **Create Feature Branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

3. **Make Changes**
   - Write code following our style guidelines
   - Add tests for new functionality
   - Update documentation as needed

4. **Test Your Changes**
   ```bash
   cargo test
   cargo clippy -- -D warnings
   cargo fmt --check
   ```

5. **Commit and Push**
   ```bash
   git add .
   git commit -m "feat: add new feature description"
   git push origin feature/your-feature-name
   ```

6. **Create Pull Request**
   - Use our PR template
   - Provide clear description of changes
   - Link related issues

### Commit Message Format

We follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>[optional scope]: <description>

[optional body]

[optional footer(s)]
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting, etc.)
- `refactor`: Code refactoring
- `test`: Adding or updating tests
- `chore`: Maintenance tasks

**Examples:**
```
feat(auth): add OAuth2 authentication support
fix(storage): resolve S3 upload timeout issue
docs: update API documentation for collections
test(core): add unit tests for rules engine
```

### Pull Request Guidelines

**PR Title Format:**
```
<type>: <description>
```

**PR Description Template:**
```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Testing
- [ ] Unit tests pass
- [ ] Integration tests pass
- [ ] Manual testing completed

## Checklist
- [ ] Code follows style guidelines
- [ ] Self-review completed
- [ ] Documentation updated
- [ ] Tests added/updated
```

## Code Style and Standards

### Rust Style Guidelines

We follow the official Rust style guide with some additions:

#### Naming Conventions
```rust
// Use snake_case for functions and variables
fn create_user_account() -> Result<User, Error> { }
let user_email = "test@example.com";

// Use PascalCase for types
struct UserAccount {
    email: String,
    created_at: DateTime<Utc>,
}

// Use SCREAMING_SNAKE_CASE for constants
const MAX_FILE_SIZE: usize = 10 * 1024 * 1024; // 10MB

// Use descriptive names
fn authenticate_user_with_jwt(token: &str) -> Result<User, AuthError> { }
```

#### Error Handling
```rust
// Use Result types for fallible operations
pub async fn create_user(request: CreateUserRequest) -> Result<User, AuthError> {
    let hashed_password = hash_password(&request.password)
        .map_err(AuthError::PasswordHashingFailed)?;
    
    let user = User {
        id: Uuid::new_v4(),
        email: request.email,
        password_hash: hashed_password,
        created_at: Utc::now(),
    };
    
    self.db.insert_user(&user).await
        .map_err(AuthError::DatabaseError)?;
    
    Ok(user)
}

// Define specific error types
#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("Invalid credentials")]
    InvalidCredentials,
    #[error("User already exists")]
    UserAlreadyExists,
    #[error("Password hashing failed: {0}")]
    PasswordHashingFailed(#[from] argon2::Error),
    #[error("Database error: {0}")]
    DatabaseError(#[from] sqlx::Error),
}
```

#### Documentation
```rust
/// Authenticates a user with email and password.
/// 
/// # Arguments
/// 
/// * `email` - The user's email address
/// * `password` - The user's plain text password
/// 
/// # Returns
/// 
/// Returns `Ok(AuthResult)` on successful authentication, containing the user
/// information and JWT token. Returns `Err(AuthError)` if authentication fails.
/// 
/// # Examples
/// 
/// ```rust
/// let result = auth_service.authenticate("user@example.com", "password").await?;
/// println!("User {} authenticated", result.user.email);
/// ```
pub async fn authenticate(
    &self,
    email: &str,
    password: &str,
) -> Result<AuthResult, AuthError> {
    // Implementation...
}
```

#### Async/Await Patterns
```rust
// Prefer async/await over manual Future handling
pub async fn process_batch_operations(
    &self,
    operations: Vec<BatchOperation>,
) -> Result<Vec<BatchResult>, BatchError> {
    let mut results = Vec::new();
    
    // Process operations concurrently
    let futures: Vec<_> = operations
        .into_iter()
        .map(|op| self.process_single_operation(op))
        .collect();
    
    let operation_results = futures::future::try_join_all(futures).await?;
    
    for result in operation_results {
        results.push(result);
    }
    
    Ok(results)
}
```

### Database Patterns

#### Query Building
```rust
// Use sqlx query builder for complex queries
pub async fn list_records_with_filter(
    &self,
    collection_id: &str,
    filter: &RecordFilter,
    pagination: &Pagination,
) -> Result<Vec<Record>, DatabaseError> {
    let mut query = QueryBuilder::new("SELECT * FROM records WHERE collection_id = ");
    query.push_bind(collection_id);
    
    if let Some(published) = filter.published {
        query.push(" AND published = ");
        query.push_bind(published);
    }
    
    if let Some(author_id) = &filter.author_id {
        query.push(" AND author_id = ");
        query.push_bind(author_id);
    }
    
    query.push(" ORDER BY created_at DESC LIMIT ");
    query.push_bind(pagination.limit);
    query.push(" OFFSET ");
    query.push_bind(pagination.offset);
    
    let records = query
        .build_query_as::<Record>()
        .fetch_all(&self.pool)
        .await?;
    
    Ok(records)
}
```

#### Migrations
```rust
// migrations/001_initial_schema.sql
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(50) NOT NULL DEFAULT 'user',
    verified BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_role ON users(role);
```

### API Design Patterns

#### Handler Structure
```rust
// handlers/collections.rs
pub async fn create_collection(
    State(app_state): State<AppState>,
    Extension(current_user): Extension<User>,
    Json(request): Json<CreateCollectionRequest>,
) -> Result<Json<Collection>, ApiError> {
    // Validate request
    request.validate()
        .map_err(ApiError::ValidationError)?;
    
    // Check permissions
    if !current_user.can_create_collections() {
        return Err(ApiError::Forbidden);
    }
    
    // Create collection
    let collection = app_state
        .collection_service
        .create_collection(request, &current_user)
        .await
        .map_err(ApiError::from)?;
    
    Ok(Json(collection))
}
```

#### Response Types
```rust
#[derive(Debug, Serialize)]
pub struct ApiResponse<T> {
    pub data: T,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pagination: Option<PaginationInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub meta: Option<serde_json::Value>,
}

#[derive(Debug, Serialize)]
pub struct ApiError {
    pub error: ErrorInfo,
}

#[derive(Debug, Serialize)]
pub struct ErrorInfo {
    pub code: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
}
```

## Architecture Deep Dive

### Request Flow

```
1. HTTP Request → Axum Router
2. Middleware Stack:
   - CORS handling
   - Rate limiting
   - Authentication
   - Request logging
3. Route Handler:
   - Request validation
   - Permission checking
   - Business logic
4. Service Layer:
   - Core business operations
   - Database interactions
   - External API calls
5. Response Generation:
   - Data serialization
   - Error handling
   - Response logging
```

### Dependency Injection

```rust
// Application state container
#[derive(Clone)]
pub struct AppState {
    pub db: Database,
    pub auth_service: AuthService,
    pub collection_service: CollectionService,
    pub storage_service: StorageService,
    pub config: Config,
}

impl AppState {
    pub async fn new(config: Config) -> Result<Self, AppError> {
        let db = Database::connect(&config.database_url).await?;
        
        let auth_service = AuthService::new(db.clone(), &config.auth);
        let collection_service = CollectionService::new(db.clone());
        let storage_service = StorageService::new(&config.storage).await?;
        
        Ok(Self {
            db,
            auth_service,
            collection_service,
            storage_service,
            config,
        })
    }
}
```

### Error Handling Strategy

```rust
// Centralized error handling
#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),
    
    #[error("Authentication error: {0}")]
    Auth(#[from] AuthError),
    
    #[error("Storage error: {0}")]
    Storage(#[from] StorageError),
    
    #[error("Validation error: {0}")]
    Validation(#[from] ValidationError),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, error_code, message) = match self {
            AppError::Auth(AuthError::InvalidCredentials) => {
                (StatusCode::UNAUTHORIZED, "INVALID_CREDENTIALS", "Invalid email or password")
            }
            AppError::Validation(e) => {
                (StatusCode::BAD_REQUEST, "VALIDATION_ERROR", &e.to_string())
            }
            _ => {
                tracing::error!("Internal server error: {}", self);
                (StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL_ERROR", "Internal server error")
            }
        };
        
        let body = Json(ApiError {
            error: ErrorInfo {
                code: error_code.to_string(),
                message: message.to_string(),
                details: None,
            },
        });
        
        (status, body).into_response()
    }
}
```

## Adding New Features

### Feature Development Checklist

1. **Design Phase**
   - [ ] Write feature specification
   - [ ] Design API endpoints
   - [ ] Plan database schema changes
   - [ ] Consider security implications

2. **Implementation Phase**
   - [ ] Create database migrations
   - [ ] Implement core business logic
   - [ ] Add API handlers
   - [ ] Write comprehensive tests

3. **Documentation Phase**
   - [ ] Update API documentation
   - [ ] Add usage examples
   - [ ] Update SDK if needed
   - [ ] Write migration guide if breaking

### Example: Adding a New Collection Field Type

1. **Define the Field Type**
```rust
// crates/core/src/collections/field_types.rs
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum FieldType {
    Text { max_length: Option<usize> },
    Number { min: Option<f64>, max: Option<f64> },
    Boolean,
    Date,
    File { allowed_types: Vec<String> },
    Relation { target_collection: String },
    // New field type
    Json { schema: Option<JsonSchema> },
}
```

2. **Add Validation Logic**
```rust
impl FieldType {
    pub fn validate_value(&self, value: &serde_json::Value) -> Result<(), ValidationError> {
        match self {
            FieldType::Json { schema } => {
                if !value.is_object() && !value.is_array() {
                    return Err(ValidationError::InvalidType {
                        expected: "object or array".to_string(),
                        actual: value.to_string(),
                    });
                }
                
                if let Some(schema) = schema {
                    schema.validate(value)?;
                }
                
                Ok(())
            }
            // ... other types
        }
    }
}
```

3. **Update Database Schema**
```sql
-- migrations/XXX_add_json_field_support.sql
ALTER TABLE collection_fields 
ADD COLUMN json_schema JSONB;
```

4. **Add Tests**
```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_json_field_validation() {
        let field_type = FieldType::Json { schema: None };
        
        // Valid JSON object
        let valid_object = serde_json::json!({"key": "value"});
        assert!(field_type.validate_value(&valid_object).is_ok());
        
        // Valid JSON array
        let valid_array = serde_json::json!([1, 2, 3]);
        assert!(field_type.validate_value(&valid_array).is_ok());
        
        // Invalid JSON (string)
        let invalid_value = serde_json::json!("not an object or array");
        assert!(field_type.validate_value(&invalid_value).is_err());
    }
}
```

## Debugging and Profiling

### Logging Configuration

```rust
// Enable structured logging
use tracing::{info, warn, error, debug, instrument};

#[instrument(skip(self))]
pub async fn authenticate_user(&self, email: &str, password: &str) -> Result<User, AuthError> {
    debug!("Attempting to authenticate user with email: {}", email);
    
    let user = self.find_user_by_email(email).await
        .map_err(|e| {
            warn!("Failed to find user by email {}: {}", email, e);
            AuthError::InvalidCredentials
        })?;
    
    if self.verify_password(password, &user.password_hash)? {
        info!("User {} authenticated successfully", user.id);
        Ok(user)
    } else {
        warn!("Invalid password for user {}", user.id);
        Err(AuthError::InvalidCredentials)
    }
}
```

### Performance Profiling

```bash
# Profile with perf (Linux)
cargo build --release
perf record --call-graph=dwarf ./target/release/ferritedb serve
perf report

# Profile with Instruments (macOS)
cargo instruments -t "Time Profiler" --bin ferritedb -- serve

# Memory profiling with valgrind
cargo build
valgrind --tool=massif ./target/debug/ferritedb serve
```

### Benchmarking

```rust
// benches/auth_benchmark.rs
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use ferritedb_core::auth::AuthService;

fn benchmark_password_hashing(c: &mut Criterion) {
    let auth_service = AuthService::new_for_testing();
    
    c.bench_function("password_hashing", |b| {
        b.iter(|| {
            auth_service.hash_password(black_box("test_password"))
        })
    });
}

criterion_group!(benches, benchmark_password_hashing);
criterion_main!(benches);
```

### Debug Tools

```bash
# Expand macros
cargo expand --bin ferritedb

# Check generated assembly
cargo asm ferritedb::auth::hash_password

# Analyze dependencies
cargo tree
cargo bloat --release

# Security audit
cargo audit
```

## Release Process

### Version Management

We follow [Semantic Versioning](https://semver.org/):
- **MAJOR**: Breaking changes
- **MINOR**: New features (backward compatible)
- **PATCH**: Bug fixes (backward compatible)

### Release Checklist

1. **Pre-release**
   - [ ] Update version in `Cargo.toml`
   - [ ] Update `CHANGELOG.md`
   - [ ] Run full test suite
   - [ ] Update documentation
   - [ ] Security audit

2. **Release**
   - [ ] Create release branch
   - [ ] Tag release version
   - [ ] Build release binaries
   - [ ] Create GitHub release
   - [ ] Publish to crates.io

3. **Post-release**
   - [ ] Update documentation site
   - [ ] Announce on social media
   - [ ] Update Docker images
   - [ ] Monitor for issues

### Automated Release Pipeline

```yaml
# .github/workflows/release.yml
name: Release

on:
  push:
    tags:
      - 'v*'

jobs:
  build:
    strategy:
      matrix:
        os: [ubuntu-latest, macos-latest, windows-latest]
    runs-on: ${{ matrix.os }}
    
    steps:
      - uses: actions/checkout@v3
      
      - name: Install Rust
        uses: actions-rs/toolchain@v1
        with:
          toolchain: stable
          
      - name: Build release
        run: cargo build --release
        
      - name: Upload artifacts
        uses: actions/upload-artifact@v3
        with:
          name: ferritedb-${{ matrix.os }}
          path: target/release/ferritedb*
```

---

## Getting Help

### Development Support

- **Discord**: Join our [developer channel](https://discord.gg/ferritedb-dev)
- **GitHub Discussions**: [Development discussions](https://github.com/ferritedb/ferritedb/discussions)
- **Office Hours**: Weekly developer office hours (see Discord for schedule)

### Resources

- **Rust Book**: [The Rust Programming Language](https://doc.rust-lang.org/book/)
- **Async Book**: [Asynchronous Programming in Rust](https://rust-lang.github.io/async-book/)
- **Axum Docs**: [Axum Web Framework](https://docs.rs/axum/)
- **SQLx Guide**: [SQLx Documentation](https://docs.rs/sqlx/)

---

*This developer guide is maintained by the FerriteDB team and community. Contributions and improvements are always welcome!*