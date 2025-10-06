# Changelog

All notable changes to FerriteDB will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Docker deployment configuration with multi-stage builds
- Development docker-compose setup with optional services
- Comprehensive project documentation (CONTRIBUTING.md, SECURITY.md, OPERATIONS.md)
- GitHub Actions CI/CD pipeline with automated testing and releases
- Issue templates for bug reports, feature requests, and questions
- Pull request template with comprehensive checklist
- Project roadmap and community guidelines
- Code of conduct based on Contributor Covenant

### Changed
- Improved Docker image security with non-root user
- Enhanced CI pipeline with security auditing and code coverage

### Fixed
- Docker build optimization with proper layer caching

## [1.0.0] - 2024-01-15

### Added
- **Core Backend Functionality**
  - SQLite database with automatic migrations
  - Dynamic collection and field management
  - JSON Schema validation for records
  - Repository pattern for data access

- **REST API**
  - Complete CRUD operations for collections and records
  - Query parameters for filtering, sorting, and pagination
  - Field selection and response formatting
  - OpenAPI 3.1 specification generation

- **Authentication & Authorization**
  - Argon2id password hashing with secure parameters
  - JWT token-based authentication with refresh tokens
  - Role-based access control (admin, user, service)
  - Rule-based access control with CEL-like expressions

- **Real-time Features**
  - WebSocket connections with authentication
  - Publish-subscribe system for collection events
  - Event filtering based on user permissions
  - Subscription management per connection

- **File Storage**
  - Local filesystem storage backend
  - S3-compatible storage backend (behind feature flag)
  - File upload validation and security checks
  - File field support in collection records

- **Admin Interface**
  - Responsive web interface with dark/light themes
  - Collection and field management UI
  - User management with role assignment
  - Data grid for record viewing and editing
  - JWT testing console for API development

- **CLI Tools**
  - Database migration commands (run, revert)
  - Admin user creation and management
  - Data import/export functionality
  - JWT token generation for service accounts

- **Security Features**
  - Comprehensive input validation and sanitization
  - CORS configuration and rate limiting
  - CSRF protection for admin interface
  - Audit logging for administrative actions
  - PII redaction in logs and responses

- **Production Features**
  - Health check endpoints (/healthz, /readyz)
  - Structured logging with correlation IDs
  - Graceful shutdown handling
  - Docker deployment support
  - Prometheus metrics (behind feature flag)

- **Documentation**
  - Comprehensive README with quickstart guide
  - API documentation with Swagger UI
  - Example collections and seed data
  - Deployment guides for various platforms

### Technical Details
- Built with Rust 1.75+ using Tokio async runtime
- Axum web framework with Tower middleware
- SQLite database with sqlx for type-safe queries
- JSON Schema validation with schemars
- Figment configuration with environment variable support
- Comprehensive test suite with cargo nextest

## [0.1.0] - 2023-12-01

### Added
- Initial project setup and basic structure
- Core domain models and database schema
- Basic REST API endpoints
- Simple authentication system
- Docker configuration
- Basic documentation

---

## Release Notes

### Version 1.0.0 - Production Ready

FerriteDB 1.0.0 marks the first production-ready release of our Rust-based backend-as-a-service solution. This release includes all core features needed to build modern applications with a single binary deployment.

**Key Highlights:**
- 🚀 **Single Binary Deployment**: Start a complete backend with `ferritedb serve`
- 🔒 **Security First**: Built-in authentication, authorization, and security hardening
- ⚡ **High Performance**: Async Rust with optimized SQLite operations
- 🎯 **Developer Friendly**: Comprehensive API, admin UI, and documentation
- 📦 **Production Ready**: Docker support, health checks, and monitoring

**Migration from 0.x:**
This is the first stable release. If you were using pre-release versions, please refer to the migration guide in the documentation.

**Breaking Changes:**
- Configuration format has been standardized (see ferritedb.toml example)
- API endpoints have been finalized with consistent naming
- Database schema has been optimized (automatic migration provided)

**Security Notes:**
- Default JWT secret must be changed in production
- Admin interface requires HTTPS in production
- File upload validation is enabled by default
- Audit logging captures all administrative actions

**Performance:**
- Optimized for single-node deployments up to 10,000 concurrent users
- SQLite WAL mode enabled for better concurrent access
- Connection pooling and query optimization implemented
- Memory usage optimized for long-running deployments

**Known Issues:**
- Large file uploads (>100MB) may timeout on slow connections
- WebSocket connections are limited to 1,000 concurrent per instance
- Full-text search is basic (advanced search planned for v1.1)

**Upgrade Path:**
For future versions, we commit to:
- Semantic versioning with clear breaking change communication
- Automatic database migrations
- Backward compatibility within major versions
- Clear migration guides for breaking changes

---

## Contributing to Changelog

When contributing to FerriteDB, please update this changelog:

1. **Add entries to [Unreleased]** section for new changes
2. **Use the following categories**:
   - `Added` for new features
   - `Changed` for changes in existing functionality
   - `Deprecated` for soon-to-be removed features
   - `Removed` for now removed features
   - `Fixed` for any bug fixes
   - `Security` for vulnerability fixes

3. **Follow the format**:
   ```markdown
   ### Added
   - Brief description of the feature (#123)
   - Another feature with reference to PR (#456)
   ```

4. **Include issue/PR references** when applicable
5. **Write for users**, not developers (focus on impact, not implementation)
6. **Group related changes** under appropriate categories

## Release Process

1. **Update version** in `Cargo.toml`
2. **Move [Unreleased] changes** to new version section
3. **Add release date** in YYYY-MM-DD format
4. **Create git tag** with `v` prefix (e.g., `v1.0.0`)
5. **GitHub Actions** automatically builds and publishes release

---

For more information about releases, see our [Release Process](CONTRIBUTING.md#release-process) documentation.