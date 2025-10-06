# Attributions and Credits

This document provides comprehensive attributions for all the technologies, libraries, projects, and individuals that have contributed to or inspired FerriteDB.

## 🏗️ Core Technologies

### Programming Language
- **[Rust](https://www.rust-lang.org/)** - Systems programming language
  - **License**: MIT/Apache-2.0
  - **Usage**: Primary programming language for the entire project
  - **Attribution**: The Rust Foundation and contributors
  - **Why**: Memory safety, performance, and excellent ecosystem

### Web Framework
- **[Axum](https://github.com/tokio-rs/axum)** - Web application framework
  - **License**: MIT
  - **Usage**: HTTP server, routing, middleware
  - **Attribution**: Tokio Contributors
  - **Version**: ^0.7.0

### Async Runtime
- **[Tokio](https://tokio.rs/)** - Asynchronous runtime
  - **License**: MIT
  - **Usage**: Async/await support, networking, timers
  - **Attribution**: Tokio Contributors
  - **Version**: ^1.0

### Database
- **[SQLite](https://sqlite.org/)** - Embedded database
  - **License**: Public Domain
  - **Usage**: Primary data storage
  - **Attribution**: D. Richard Hipp and SQLite contributors
  - **Why**: Zero-configuration, serverless, self-contained

- **[SQLx](https://github.com/launchbadge/sqlx)** - Async SQL toolkit
  - **License**: MIT/Apache-2.0
  - **Usage**: Database connectivity and query building
  - **Attribution**: LaunchBadge and contributors
  - **Version**: ^0.7.0

## 🔐 Security & Authentication

### Password Hashing
- **[Argon2](https://github.com/P-H-C/phc-winner-argon2)** - Password hashing algorithm
  - **License**: CC0/Apache-2.0
  - **Usage**: Secure password hashing
  - **Attribution**: Password Hashing Competition winners
  - **Implementation**: [argon2](https://crates.io/crates/argon2) crate

### JWT Tokens
- **[jsonwebtoken](https://github.com/Keats/jsonwebtoken)** - JWT implementation
  - **License**: MIT
  - **Usage**: JWT token generation and validation
  - **Attribution**: Vincent Prouillet and contributors
  - **Version**: ^9.0

### Cryptography
- **[ring](https://github.com/briansmith/ring)** - Cryptographic primitives
  - **License**: ISC/MIT/OpenSSL
  - **Usage**: Cryptographic operations
  - **Attribution**: Brian Smith and contributors

## 📊 Serialization & Data Formats

### JSON Processing
- **[serde](https://serde.rs/)** - Serialization framework
  - **License**: MIT/Apache-2.0
  - **Usage**: JSON serialization/deserialization
  - **Attribution**: David Tolnay and contributors
  - **Version**: ^1.0

- **[serde_json](https://github.com/serde-rs/json)** - JSON support for serde
  - **License**: MIT/Apache-2.0
  - **Usage**: JSON parsing and generation
  - **Attribution**: Serde contributors

### TOML Configuration
- **[toml](https://github.com/toml-rs/toml)** - TOML parser
  - **License**: MIT/Apache-2.0
  - **Usage**: Configuration file parsing
  - **Attribution**: Alex Crichton and contributors

## 🌐 HTTP & Networking

### HTTP Client
- **[reqwest](https://github.com/seanmonstar/reqwest)** - HTTP client
  - **License**: MIT/Apache-2.0
  - **Usage**: External HTTP requests
  - **Attribution**: Sean McArthur and contributors

### WebSocket Support
- **[tokio-tungstenite](https://github.com/snapview/tokio-tungstenite)** - WebSocket implementation
  - **License**: MIT
  - **Usage**: Real-time WebSocket connections
  - **Attribution**: Snapview and contributors

## 📁 File Storage

### Local Storage
- **[tokio-fs](https://docs.rs/tokio/latest/tokio/fs/)** - Async filesystem operations
  - **License**: MIT
  - **Usage**: Local file operations
  - **Attribution**: Tokio Contributors

### S3 Compatible Storage
- **[aws-sdk-s3](https://github.com/awslabs/aws-sdk-rust)** - AWS S3 SDK
  - **License**: Apache-2.0
  - **Usage**: S3-compatible storage backend
  - **Attribution**: Amazon Web Services and contributors

## 🧪 Testing & Development

### Testing Framework
- **[tokio-test](https://docs.rs/tokio-test/)** - Async testing utilities
  - **License**: MIT
  - **Usage**: Async test support
  - **Attribution**: Tokio Contributors

### Temporary Files
- **[tempfile](https://github.com/Stebalien/tempfile)** - Temporary file handling
  - **License**: MIT/Apache-2.0
  - **Usage**: Test file management
  - **Attribution**: Steven Allen and contributors

## 🔧 CLI & Utilities

### Command Line Interface
- **[clap](https://github.com/clap-rs/clap)** - Command line argument parser
  - **License**: MIT/Apache-2.0
  - **Usage**: CLI interface and argument parsing
  - **Attribution**: Kevin K. and contributors
  - **Version**: ^4.0

### Logging
- **[tracing](https://github.com/tokio-rs/tracing)** - Application-level tracing
  - **License**: MIT
  - **Usage**: Structured logging and diagnostics
  - **Attribution**: Tokio Contributors

- **[tracing-subscriber](https://github.com/tokio-rs/tracing)** - Tracing subscriber implementations
  - **License**: MIT
  - **Usage**: Log formatting and output
  - **Attribution**: Tokio Contributors

### Error Handling
- **[thiserror](https://github.com/dtolnay/thiserror)** - Error derive macro
  - **License**: MIT/Apache-2.0
  - **Usage**: Error type definitions
  - **Attribution**: David Tolnay

- **[anyhow](https://github.com/dtolnay/anyhow)** - Error handling
  - **License**: MIT/Apache-2.0
  - **Usage**: Error context and chaining
  - **Attribution**: David Tolnay

## 🎨 Frontend & UI

### Admin Interface
- **[HTML5](https://html.spec.whatwg.org/)** - Markup language
  - **License**: W3C Software License
  - **Usage**: Admin interface structure
  - **Attribution**: WHATWG and W3C

- **[CSS3](https://www.w3.org/Style/CSS/)** - Styling language
  - **License**: W3C Software License
  - **Usage**: Admin interface styling
  - **Attribution**: W3C CSS Working Group

- **[JavaScript (ES2020)](https://tc39.es/ecma262/)** - Programming language
  - **License**: Ecma International
  - **Usage**: Admin interface interactivity
  - **Attribution**: TC39 and Ecma International

## 📖 Documentation

### API Documentation
- **[OpenAPI 3.0](https://spec.openapis.org/oas/v3.0.3)** - API specification format
  - **License**: Apache-2.0
  - **Usage**: API documentation generation
  - **Attribution**: OpenAPI Initiative

- **[Swagger UI](https://swagger.io/tools/swagger-ui/)** - API documentation interface
  - **License**: Apache-2.0
  - **Usage**: Interactive API documentation
  - **Attribution**: SmartBear Software

### Documentation Generation
- **[rustdoc](https://doc.rust-lang.org/rustdoc/)** - Rust documentation tool
  - **License**: MIT/Apache-2.0
  - **Usage**: Code documentation generation
  - **Attribution**: Rust Project Developers

## 🐳 Containerization & Deployment

### Container Runtime
- **[Docker](https://www.docker.com/)** - Containerization platform
  - **License**: Apache-2.0
  - **Usage**: Application containerization
  - **Attribution**: Docker, Inc.

### Base Images
- **[Debian](https://www.debian.org/)** - Operating system
  - **License**: Debian Free Software Guidelines
  - **Usage**: Docker base image
  - **Attribution**: Debian Project

- **[Alpine Linux](https://alpinelinux.org/)** - Security-oriented Linux distribution
  - **License**: Various (mostly GPL)
  - **Usage**: Lightweight Docker images
  - **Attribution**: Alpine Linux Development Team

## 🔄 CI/CD & Automation

### Continuous Integration
- **[GitHub Actions](https://github.com/features/actions)** - CI/CD platform
  - **License**: GitHub Terms of Service
  - **Usage**: Automated testing and deployment
  - **Attribution**: GitHub, Inc.

### Build Tools
- **[Cargo](https://doc.rust-lang.org/cargo/)** - Rust package manager
  - **License**: MIT/Apache-2.0
  - **Usage**: Build system and dependency management
  - **Attribution**: Rust Project Developers

- **[just](https://github.com/casey/just)** - Command runner
  - **License**: CC0-1.0
  - **Usage**: Development task automation
  - **Attribution**: Casey Rodarmor

## 🌟 Inspirational Projects

### Direct Inspiration
- **[PocketBase](https://pocketbase.io/)** - Backend-as-a-Service
  - **License**: MIT
  - **Inspiration**: Single binary deployment, admin interface, real-time features
  - **Attribution**: Gani Georgiev and contributors
  - **Note**: FerriteDB draws architectural inspiration from PocketBase's approach to BaaS

- **[Supabase](https://supabase.com/)** - Open source Firebase alternative
  - **License**: Apache-2.0
  - **Inspiration**: Developer experience, real-time subscriptions, row-level security
  - **Attribution**: Supabase Inc. and contributors

- **[Firebase](https://firebase.google.com/)** - Google's mobile and web application development platform
  - **License**: Proprietary
  - **Inspiration**: Real-time database, authentication patterns, developer experience
  - **Attribution**: Google LLC

### Technical Inspiration
- **[PostgREST](https://postgrest.org/)** - REST API from PostgreSQL schema
  - **License**: MIT
  - **Inspiration**: Automatic API generation from database schema
  - **Attribution**: Joe Nelson and contributors

- **[Hasura](https://hasura.io/)** - GraphQL API platform
  - **License**: Apache-2.0
  - **Inspiration**: Real-time subscriptions, permission system
  - **Attribution**: Hasura Inc.

## 🧠 Algorithms & Concepts

### Rules Engine
- **[Common Expression Language (CEL)](https://github.com/google/cel-spec)** - Expression language
  - **License**: Apache-2.0
  - **Inspiration**: Rule expression syntax and evaluation
  - **Attribution**: Google LLC

### Authentication Patterns
- **[OAuth 2.0](https://oauth.net/2/)** - Authorization framework
  - **License**: IETF
  - **Inspiration**: Token-based authentication patterns
  - **Attribution**: IETF OAuth Working Group

- **[JWT (JSON Web Tokens)](https://jwt.io/)** - Token standard
  - **License**: IETF
  - **Usage**: Token format and validation
  - **Attribution**: IETF and JWT.io contributors

## 📚 Educational Resources

### Books & Publications
- **"The Rust Programming Language"** by Steve Klabnik and Carol Nichols
  - **Publisher**: No Starch Press
  - **Influence**: Rust best practices and patterns

- **"Zero To Production In Rust"** by Luca Palmieri
  - **Publisher**: Self-published
  - **Influence**: Web service architecture in Rust

### Online Resources
- **[Rust by Example](https://doc.rust-lang.org/rust-by-example/)** - Learning resource
  - **License**: MIT/Apache-2.0
  - **Usage**: Code patterns and examples
  - **Attribution**: Rust Project Developers

- **[The Async Book](https://rust-lang.github.io/async-book/)** - Async programming guide
  - **License**: MIT/Apache-2.0
  - **Usage**: Async/await patterns
  - **Attribution**: Rust Async Working Group

## 🛠️ Development Tools

### Code Quality
- **[clippy](https://github.com/rust-lang/rust-clippy)** - Rust linter
  - **License**: MIT/Apache-2.0
  - **Usage**: Code quality and style checking
  - **Attribution**: Rust Project Developers

- **[rustfmt](https://github.com/rust-lang/rustfmt)** - Code formatter
  - **License**: MIT/Apache-2.0
  - **Usage**: Code formatting
  - **Attribution**: Rust Project Developers

### Security Auditing
- **[cargo-audit](https://github.com/RustSec/rustsec)** - Security vulnerability scanner
  - **License**: MIT/Apache-2.0
  - **Usage**: Dependency security auditing
  - **Attribution**: RustSec Advisory Database contributors

## 🌍 Community & Standards

### Standards Organizations
- **[Internet Engineering Task Force (IETF)](https://www.ietf.org/)** - Internet standards
  - **Standards Used**: HTTP, JWT, OAuth, WebSocket
  - **Attribution**: IETF contributors and working groups

- **[World Wide Web Consortium (W3C)](https://www.w3.org/)** - Web standards
  - **Standards Used**: HTML, CSS, HTTP
  - **Attribution**: W3C members and contributors

### Open Source Communities
- **[Rust Community](https://www.rust-lang.org/community)** - Programming language community
  - **Contribution**: Language development, ecosystem, support
  - **Attribution**: Rust Foundation and global Rust community

- **[GitHub Open Source Community](https://github.com/open-source)** - Development platform
  - **Contribution**: Code hosting, collaboration tools, CI/CD
  - **Attribution**: GitHub, Inc. and open source contributors

## 📄 License Compliance

### License Summary
This project uses dependencies under the following licenses:
- **MIT License**: Most permissive, allows commercial use
- **Apache License 2.0**: Permissive with patent grant
- **ISC License**: Simplified BSD-style license
- **Public Domain**: No restrictions
- **CC0**: Creative Commons public domain dedication

### Full License Texts
Complete license texts for all dependencies can be found in the `licenses/` directory of this repository.

### Compliance Statement
FerriteDB complies with all license requirements of its dependencies. All required attributions are included in this document and in the software distribution.

## 🙏 Special Thanks

### Individual Contributors
- **[@foozio](https://github.com/foozio)** - Project creator and lead maintainer
- All community contributors who have submitted issues, pull requests, and feedback

### Organizations
- **The Rust Foundation** - For maintaining and advancing the Rust programming language
- **Mozilla Foundation** - For originally sponsoring Rust development
- **GitHub** - For providing free hosting and CI/CD for open source projects
- **All open source maintainers** - For creating and maintaining the libraries we depend on

### Beta Testers & Early Adopters
- Community members who provided early feedback and testing
- Users who reported bugs and suggested improvements
- Contributors who helped with documentation and examples

## 📝 Attribution Requirements

When using FerriteDB in your projects, please consider:

1. **Including this attribution file** in your distributions
2. **Crediting FerriteDB** in your documentation or about pages
3. **Linking back to the project** when appropriate
4. **Contributing back** improvements and bug fixes when possible

## 🔄 Updates

This attribution document is maintained alongside the project and updated with each release. If you notice any missing attributions or incorrect information, please open an issue or submit a pull request.

---

**Last Updated**: October 2025  
**FerriteDB Version**: 1.0.0  
**Maintainer**: [@foozio](https://github.com/foozio)

*This document represents our commitment to recognizing and crediting all the amazing work that makes FerriteDB possible. Thank you to everyone who contributes to the open source ecosystem!*