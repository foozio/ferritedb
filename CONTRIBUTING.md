# Contributing to FerriteDB

Thank you for your interest in contributing to FerriteDB! This document provides guidelines and information for contributors.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Project Structure](#project-structure)
- [Coding Standards](#coding-standards)
- [Testing Guidelines](#testing-guidelines)
- [Pull Request Process](#pull-request-process)
- [Release Process](#release-process)
- [Community](#community)

## Code of Conduct

This project adheres to a code of conduct that we expect all contributors to follow. Please be respectful, inclusive, and constructive in all interactions.

## Getting Started

### Prerequisites

- Rust 1.75 or later
- SQLite 3.35 or later
- Git
- Docker (optional, for containerized development)

### Quick Start

1. Fork the repository
2. Clone your fork: `git clone https://github.com/yourusername/ferritedb.git`
3. Set up the development environment (see below)
4. Create a feature branch: `git checkout -b feature/your-feature-name`
5. Make your changes and test them
6. Submit a pull request

## Development Setup

### Local Development

```bash
# Clone the repository
git clone https://github.com/ferritedb/ferritedb.git
cd ferritedb

# Install dependencies and build
cargo build

# Run tests
cargo test

# Start development server
cargo run -- serve

# Or use the justfile for common tasks
just dev      # Start development server with auto-reload
just test     # Run all tests
just lint     # Run linting
just fmt      # Format code
```

### Docker Development

```bash
# Start development environment
docker-compose -f docker-compose.dev.yml up

# With additional services
docker-compose -f docker-compose.dev.yml --profile with-postgres --profile with-redis up

# Build and test in container
docker-compose -f docker-compose.dev.yml exec ferritedb-dev cargo test
```

### Environment Configuration

Create a `.env` file for local development:

```bash
# Database
FERRITEDB_DATABASE_URL=sqlite:data/ferritedb.db

# Authentication
FERRITEDB_AUTH_JWT_SECRET=your-development-secret

# Storage
FERRITEDB_STORAGE_BACKEND=local
FERRITEDB_STORAGE_LOCAL_BASE_PATH=data/storage

# Logging
RUST_LOG=debug
```

## Project Structure

```
ferritedb/
├── crates/
│   ├── server/          # Web server, routes, middleware
│   ├── core/            # Business logic, collections, auth
│   ├── storage/         # File storage backends
│   ├── rules/           # Rule evaluation engine
│   └── sdk-rs/          # Rust client SDK
├── migrations/          # Database migrations
├── tests/               # Integration tests
├── docs/                # Documentation
├── examples/            # Usage examples
└── admin/               # Admin UI (if separate)
```

### Key Components

- **Core Engine**: Business logic and domain models
- **Web Server**: HTTP/WebSocket handling with Axum
- **Rules Engine**: CEL-like expression evaluation
- **Storage System**: Pluggable file storage backends
- **Authentication**: JWT-based auth with role management

## Coding Standards

### Rust Guidelines

- Follow the [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/)
- Use `cargo fmt` for consistent formatting
- Run `cargo clippy` and address all warnings
- Write comprehensive documentation with `///` comments
- Use meaningful variable and function names
- Prefer explicit error handling over panics

### Code Style

```rust
// Good: Clear, documented function
/// Validates a collection name according to FerriteDB naming rules.
/// 
/// # Arguments
/// * `name` - The collection name to validate
/// 
/// # Returns
/// * `Ok(())` if valid
/// * `Err(ValidationError)` if invalid
/// 
/// # Examples
/// ```
/// assert!(validate_collection_name("users").is_ok());
/// assert!(validate_collection_name("123invalid").is_err());
/// ```
pub fn validate_collection_name(name: &str) -> Result<(), ValidationError> {
    if name.is_empty() || name.len() > 64 {
        return Err(ValidationError::InvalidLength);
    }
    
    if !name.chars().all(|c| c.is_alphanumeric() || c == '_') {
        return Err(ValidationError::InvalidCharacters);
    }
    
    Ok(())
}
```

### Error Handling

- Use `thiserror` for error types
- Provide meaningful error messages
- Include context in error chains
- Use `Result<T, E>` consistently

```rust
#[derive(Debug, thiserror::Error)]
pub enum ValidationError {
    #[error("Collection name must be 1-64 characters long")]
    InvalidLength,
    
    #[error("Collection name can only contain alphanumeric characters and underscores")]
    InvalidCharacters,
    
    #[error("Collection name '{name}' is reserved")]
    ReservedName { name: String },
}
```

### Database Interactions

- Use sqlx with compile-time checked queries
- Always use parameterized queries
- Handle database errors gracefully
- Use transactions for multi-step operations

```rust
// Good: Type-safe, parameterized query
let collection = sqlx::query_as!(
    Collection,
    "SELECT id, name, schema_json, created_at FROM collections WHERE name = ?",
    name
)
.fetch_optional(&pool)
.await?;
```

## Testing Guidelines

### Test Categories

1. **Unit Tests**: Test individual functions and modules
2. **Integration Tests**: Test component interactions
3. **End-to-End Tests**: Test complete workflows
4. **Performance Tests**: Test under load

### Writing Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    
    #[tokio::test]
    async fn test_collection_creation() {
        // Arrange
        let temp_dir = TempDir::new().unwrap();
        let db_url = format!("sqlite:{}/test.db", temp_dir.path().display());
        let pool = create_test_pool(&db_url).await;
        
        // Act
        let result = create_collection(&pool, "test_collection", &schema).await;
        
        // Assert
        assert!(result.is_ok());
        let collection = result.unwrap();
        assert_eq!(collection.name, "test_collection");
    }
}
```

### Test Data

- Use temporary databases for tests
- Clean up test data after each test
- Use realistic but minimal test data
- Mock external dependencies

### Running Tests

```bash
# Run all tests
cargo test

# Run specific test
cargo test test_collection_creation

# Run with output
cargo test -- --nocapture

# Run integration tests only
cargo test --test integration_tests
```

## Pull Request Process

### Before Submitting

1. **Create an Issue**: For significant changes, create an issue first to discuss the approach
2. **Branch Naming**: Use descriptive branch names like `feature/add-oauth2-support` or `fix/collection-validation-bug`
3. **Commit Messages**: Write clear, descriptive commit messages following conventional commits format

### Commit Message Format

```
type(scope): description

[optional body]

[optional footer]
```

Examples:
- `feat(auth): add OAuth2 Google provider support`
- `fix(collections): validate field names properly`
- `docs(api): update OpenAPI specification`
- `test(rules): add comprehensive rule evaluation tests`

### Pull Request Checklist

- [ ] Code follows the project's coding standards
- [ ] All tests pass (`cargo test`)
- [ ] Code is properly formatted (`cargo fmt`)
- [ ] No clippy warnings (`cargo clippy`)
- [ ] Documentation is updated if needed
- [ ] CHANGELOG.md is updated for user-facing changes
- [ ] Security implications are considered
- [ ] Performance impact is evaluated

### Review Process

1. **Automated Checks**: CI must pass (tests, linting, security audit)
2. **Code Review**: At least one maintainer review required
3. **Testing**: Reviewers may test the changes locally
4. **Documentation**: Ensure documentation is clear and complete

### Merge Requirements

- All CI checks must pass
- At least one approving review from a maintainer
- No unresolved conversations
- Branch is up to date with main

## Release Process

### Versioning

FerriteDB follows [Semantic Versioning](https://semver.org/):
- **MAJOR**: Breaking changes
- **MINOR**: New features (backward compatible)
- **PATCH**: Bug fixes (backward compatible)

### Release Checklist

1. Update version in `Cargo.toml`
2. Update `CHANGELOG.md`
3. Create release PR
4. Tag release after merge
5. Automated CI builds and publishes artifacts

## Community

### Communication Channels

- **GitHub Issues**: Bug reports and feature requests
- **GitHub Discussions**: General questions and community discussion
- **Discord**: Real-time chat (link in README)

### Getting Help

1. Check existing documentation and issues
2. Search GitHub Discussions
3. Create a new issue with detailed information
4. Join the Discord for real-time help

### Reporting Bugs

When reporting bugs, please include:

- FerriteDB version
- Operating system and version
- Rust version
- Steps to reproduce
- Expected vs actual behavior
- Relevant logs or error messages
- Minimal reproduction case if possible

### Suggesting Features

For feature requests:

- Check if it already exists in issues
- Describe the use case and problem it solves
- Provide examples of how it would work
- Consider implementation complexity
- Be open to discussion and alternatives

## Development Tips

### Performance Considerations

- Profile before optimizing
- Use `cargo bench` for benchmarks
- Consider memory usage and allocations
- Test with realistic data sizes
- Monitor database query performance

### Security Best Practices

- Never commit secrets or credentials
- Validate all user inputs
- Use parameterized queries
- Follow OWASP guidelines
- Consider security implications of changes
- Run `cargo audit` regularly

### Debugging

```bash
# Enable debug logging
RUST_LOG=debug cargo run -- serve

# Use rust-gdb for debugging
rust-gdb target/debug/ferritedb

# Profile with perf (Linux)
cargo build --release
perf record target/release/ferritedb serve
perf report
```

### Useful Tools

- **cargo-watch**: Auto-rebuild on file changes
- **cargo-audit**: Security vulnerability scanning
- **cargo-deny**: License and dependency checking
- **cargo-machete**: Find unused dependencies
- **sqlx-cli**: Database migration management

## License

By contributing to FerriteDB, you agree that your contributions will be licensed under the same license as the project (MIT License).

---

Thank you for contributing to FerriteDB! Your efforts help make this project better for everyone.