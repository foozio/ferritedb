# FerriteDB Frequently Asked Questions (FAQ)

This document answers the most commonly asked questions about FerriteDB, covering everything from basic concepts to advanced usage scenarios.

## Table of Contents

- [General Questions](#general-questions)
- [Technical Questions](#technical-questions)
- [Deployment and Operations](#deployment-and-operations)
- [Development and Integration](#development-and-integration)
- [Performance and Scaling](#performance-and-scaling)
- [Security and Compliance](#security-and-compliance)
- [Comparison with Other Solutions](#comparison-with-other-solutions)
- [Licensing and Commercial Use](#licensing-and-commercial-use)
- [Community and Support](#community-and-support)

## General Questions

### What is FerriteDB?

FerriteDB is a modern, high-performance backend-as-a-service (BaaS) built in Rust. It provides a complete backend solution with dynamic collections, authentication, file storage, real-time features, and a built-in admin interface - all in a single binary.

### Why choose FerriteDB over other BaaS solutions?

**Key advantages:**

- **Single Binary**: No complex setup or multiple services to manage
- **High Performance**: Built in Rust for maximum speed and efficiency
- **Type Safety**: Strong typing prevents runtime errors
- **Memory Safety**: No memory leaks or buffer overflows
- **Dynamic Schema**: Create and modify collections without migrations
- **Built-in Features**: Authentication, file storage, real-time, admin UI included
- **Self-hosted**: Full control over your data and infrastructure
- **Open Source**: MIT licensed with active community development

### What makes FerriteDB different from Firebase or Supabase?

| Feature | FerriteDB | Firebase | Supabase |
|---------|-----------|----------|----------|
| **Deployment** | Single binary | Cloud only | Self-hosted or cloud |
| **Language** | Rust | Proprietary | TypeScript/PostgreSQL |
| **Database** | SQLite/PostgreSQL | Firestore | PostgreSQL |
| **Schema** | Dynamic | NoSQL | SQL with migrations |
| **Real-time** | WebSocket | WebSocket | WebSocket |
| **Pricing** | Free (self-hosted) | Pay-per-use | Freemium |
| **Vendor Lock-in** | None | High | Low |

### Is FerriteDB production-ready?

FerriteDB is actively developed and used in production by several organizations. However, as with any software:

- **Current Status**: Beta/RC stage with regular releases
- **Production Use**: Suitable for production with proper testing
- **Breaking Changes**: Possible until v1.0 (with migration guides)
- **Support**: Community support with commercial support planned
- **Monitoring**: Comprehensive logging and metrics available

### What are the system requirements?

**Minimum Requirements:**
- CPU: 1 vCPU
- RAM: 512 MB
- Storage: 1 GB
- OS: Linux, macOS, or Windows

**Recommended for Production:**
- CPU: 2+ vCPUs
- RAM: 2+ GB
- Storage: 10+ GB SSD
- OS: Linux (Ubuntu 20.04+ or CentOS 8+)

## Technical Questions

### What databases does FerriteDB support?

**Primary Support:**
- **SQLite**: Default, embedded database (recommended for single-instance deployments)
- **PostgreSQL**: For enterprise deployments requiring advanced features

**Planned Support:**
- **MySQL/MariaDB**: Planned for future releases
- **CockroachDB**: For distributed deployments

### How does the dynamic schema system work?

FerriteDB allows you to create and modify collections without traditional database migrations:

```json
{
  "name": "posts",
  "schema": {
    "fields": [
      {
        "name": "title",
        "type": "text",
        "required": true
      },
      {
        "name": "content",
        "type": "text"
      }
    ]
  }
}
```

**Benefits:**
- No downtime for schema changes
- Automatic table generation
- Field validation at runtime
- Backward compatibility maintained

### What field types are supported?

| Type | Description | Example |
|------|-------------|---------|
| `text` | String data | "Hello World" |
| `number` | Integer or float | 42, 3.14 |
| `boolean` | True/false | true, false |
| `date` | ISO 8601 dates | "2023-12-01T10:00:00Z" |
| `email` | Email addresses | "user@example.com" |
| `url` | URLs | "https://example.com" |
| `file` | File references | File upload metadata |
| `relation` | References to other records | Foreign key relationships |
| `json` | Arbitrary JSON data | {"key": "value"} |

### How does authentication work?

FerriteDB uses JWT-based authentication with multiple strategies:

**Authentication Methods:**
- **Email/Password**: Traditional login with secure password hashing (Argon2)
- **API Keys**: For service-to-service communication
- **OAuth**: Planned for future releases (Google, GitHub, etc.)

**Security Features:**
- Argon2 password hashing
- Configurable token expiration
- Refresh token support
- Role-based access control
- Rate limiting

### What is the rules engine?

The rules engine provides fine-grained access control using CEL-like expressions:

```javascript
// Collection-level rule
user.role == "admin" || record.published == true

// Field-level rule
user.role == "admin" || (user.id == record.author_id && field.name != "password")

// Context-aware rule
user.role == "admin" || (record.author_id == user.id && request.method == "GET")
```

**Available Context:**
- `user`: Current authenticated user
- `record`: The record being accessed
- `request`: HTTP request information
- `field`: Field being accessed (for field-level rules)

### How does file storage work?

FerriteDB supports multiple storage backends:

**Local Storage:**
- Files stored on local filesystem
- Configurable path and permissions
- Suitable for single-instance deployments

**S3-Compatible Storage:**
- AWS S3, MinIO, DigitalOcean Spaces
- Signed URLs for secure access
- Automatic cleanup and lifecycle management

**Features:**
- File type validation
- Size limits and quotas
- Image transformation (planned)
- CDN integration (planned)

### What real-time features are available?

FerriteDB provides WebSocket-based real-time updates:

**Event Types:**
- Record created/updated/deleted
- Collection schema changes
- User presence tracking
- Custom events

**Features:**
- Automatic reconnection
- Event filtering
- Subscription management
- Scalable to thousands of connections

## Deployment and Operations

### How do I deploy FerriteDB?

**Deployment Options:**

1. **Single Binary**
```bash
# Download and run
wget https://github.com/foozio/ferritedb/releases/latest/download/ferritedb-linux-x86_64.tar.gz
tar -xzf ferritedb-linux-x86_64.tar.gz
./ferritedb serve --config ferritedb.toml
```

2. **Docker**
```bash
docker run -d \
  --name ferritedb \
  -p 8090:8090 \
  -v ferritedb_data:/app/data \
  ferritedb/ferritedb:latest
```

3. **Docker Compose**
```yaml
version: '3.8'
services:
  ferritedb:
    image: ferritedb/ferritedb:latest
    ports:
      - "8090:8090"
    volumes:
      - ferritedb_data:/app/data
```

4. **Kubernetes**
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ferritedb
spec:
  replicas: 2
  selector:
    matchLabels:
      app: ferritedb
  template:
    spec:
      containers:
      - name: ferritedb
        image: ferritedb/ferritedb:latest
        ports:
        - containerPort: 8090
```

### Can FerriteDB scale horizontally?

**Current Scaling:**
- **Vertical Scaling**: Fully supported (more CPU/RAM)
- **Horizontal Scaling**: Limited (stateless design with shared database)

**Scaling Strategies:**
- Multiple instances with load balancer
- Shared PostgreSQL database
- Read replicas for read-heavy workloads
- CDN for static file serving

**Future Plans:**
- Native clustering support
- Distributed caching
- Automatic sharding

### How do I backup and restore data?

**SQLite Backup:**
```bash
# Backup
sqlite3 data/ferritedb.db ".backup backup.db"

# Restore
cp backup.db data/ferritedb.db
```

**PostgreSQL Backup:**
```bash
# Backup
pg_dump ferritedb > backup.sql

# Restore
psql ferritedb < backup.sql
```

**File Storage Backup:**
```bash
# Local files
tar -czf files-backup.tar.gz data/files/

# S3 files (already backed up in S3)
aws s3 sync s3://your-bucket/ ./backup/
```

### How do I monitor FerriteDB?

**Built-in Monitoring:**
- Health check endpoints (`/api/health`, `/api/readyz`)
- Prometheus metrics (`/metrics`)
- Structured logging (JSON format)
- Performance tracing

**Monitoring Stack:**
- **Metrics**: Prometheus + Grafana
- **Logs**: ELK Stack or Loki
- **Tracing**: Jaeger (planned)
- **Alerting**: Alertmanager

### What about high availability?

**HA Setup:**
1. **Load Balancer**: Nginx, HAProxy, or cloud LB
2. **Multiple Instances**: 2+ FerriteDB instances
3. **Shared Database**: PostgreSQL with replication
4. **Shared Storage**: S3 or distributed filesystem
5. **Health Checks**: Automatic failover

**Considerations:**
- Database is the single point of failure
- File storage needs to be shared
- Session state is stateless (JWT tokens)

## Development and Integration

### What SDKs are available?

**Official SDKs:**
- **Rust**: Native SDK with full type safety
- **JavaScript/TypeScript**: For web and Node.js applications
- **Python**: For Python applications and Django/FastAPI integration

**Planned SDKs:**
- **Go**: For Go applications
- **Java**: For Java/Kotlin applications
- **C#**: For .NET applications
- **PHP**: For PHP applications

### How do I integrate with existing applications?

**Integration Strategies:**

1. **API Gateway Pattern**
```
Client App → API Gateway → FerriteDB
                      → Existing Services
```

2. **Microservices Pattern**
```
Client App → Load Balancer → FerriteDB (User Data)
                          → Auth Service
                          → Payment Service
```

3. **Hybrid Pattern**
```
Client App → FerriteDB (Primary)
          → Legacy API (Specific Features)
```

### Can I extend FerriteDB functionality?

**Current Extension Points:**
- Custom middleware (Rust)
- Webhook integrations
- External authentication providers
- Custom storage backends

**Planned Extension System:**
- Plugin architecture
- Custom field types
- Custom rules functions
- Event handlers

### How do I migrate from other BaaS solutions?

**Migration Strategies:**

**From Firebase:**
1. Export Firestore data
2. Transform to FerriteDB schema
3. Import using bulk API
4. Update client applications
5. Switch DNS/routing

**From Supabase:**
1. Export PostgreSQL data
2. Create equivalent collections
3. Migrate authentication data
4. Update client SDKs
5. Test and switch

**Migration Tools:**
- Data export/import utilities
- Schema conversion tools
- Client SDK migration guides

### What testing strategies are recommended?

**Testing Approaches:**

1. **Unit Tests**
```rust
#[tokio::test]
async fn test_create_user() {
    let client = test_client().await;
    let user = client.auth().register("test@example.com", "password").await?;
    assert_eq!(user.email, "test@example.com");
}
```

2. **Integration Tests**
```typescript
describe('Posts API', () => {
  it('should create and retrieve posts', async () => {
    const client = new FerriteDB({ url: TEST_URL });
    await client.auth.login('test@example.com', 'password');
    
    const post = await client.collection('posts').create({
      title: 'Test Post',
      content: 'Test content'
    });
    
    expect(post.title).toBe('Test Post');
  });
});
```

3. **End-to-End Tests**
```python
def test_complete_workflow():
    # Test complete user journey
    client = FerriteDB({"url": TEST_URL})
    
    # Register user
    user = await client.auth.register("test@example.com", "password")
    
    # Create post
    post = await client.collection("posts").create({
        "title": "Test Post",
        "content": "Test content"
    })
    
    # Verify real-time updates
    # ... test WebSocket events
```

## Performance and Scaling

### What performance can I expect?

**Benchmark Results** (on modern hardware):

| Operation | Requests/sec | Latency (p95) |
|-----------|--------------|---------------|
| Simple GET | 10,000+ | <5ms |
| POST with validation | 5,000+ | <10ms |
| File upload (1MB) | 100+ | <100ms |
| WebSocket messages | 50,000+ | <1ms |

**Factors Affecting Performance:**
- Hardware specifications
- Database choice (SQLite vs PostgreSQL)
- Network latency
- Payload size
- Concurrent connections

### How do I optimize performance?

**Database Optimization:**
```toml
[database]
max_connections = 20
connection_timeout = 30
query_timeout = 10
```

**Server Optimization:**
```toml
[server]
max_concurrent_requests = 1000
request_timeout = 30
keep_alive_timeout = 75
```

**Application-Level:**
- Use pagination for large datasets
- Implement client-side caching
- Use field selection to reduce payload
- Batch operations when possible
- Optimize database queries

### What are the scaling limits?

**Current Limits:**
- **Concurrent Connections**: 10,000+ WebSocket connections
- **Database Size**: Limited by SQLite (281 TB) or PostgreSQL (unlimited)
- **File Storage**: Limited by available disk space or S3 limits
- **Request Rate**: 10,000+ requests/second per instance

**Scaling Bottlenecks:**
- Database connections
- Memory usage
- Disk I/O
- Network bandwidth

### How do I handle traffic spikes?

**Strategies:**

1. **Auto-scaling** (Kubernetes)
```yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: ferritedb-hpa
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: ferritedb
  minReplicas: 2
  maxReplicas: 10
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
```

2. **Load Balancing**
```nginx
upstream ferritedb_backend {
    least_conn;
    server ferritedb1:8090 max_fails=3 fail_timeout=30s;
    server ferritedb2:8090 max_fails=3 fail_timeout=30s;
    server ferritedb3:8090 max_fails=3 fail_timeout=30s;
}
```

3. **Caching**
- Redis for session data
- CDN for static files
- Application-level caching

## Security and Compliance

### How secure is FerriteDB?

**Security Features:**
- **Memory Safety**: Rust prevents buffer overflows and memory leaks
- **Input Validation**: All inputs validated and sanitized
- **SQL Injection Prevention**: Parameterized queries only
- **XSS Protection**: Content Security Policy headers
- **CSRF Protection**: Token-based CSRF prevention
- **Rate Limiting**: API abuse prevention
- **Audit Logging**: All operations logged

### What authentication methods are supported?

**Current Methods:**
- Email/password with Argon2 hashing
- API keys for service accounts
- JWT tokens with configurable expiration

**Planned Methods:**
- OAuth 2.0 (Google, GitHub, etc.)
- SAML for enterprise
- Multi-factor authentication (MFA)
- WebAuthn/FIDO2

### Is FerriteDB GDPR compliant?

**GDPR Features:**
- **Data Portability**: Export user data in standard formats
- **Right to Erasure**: Delete user data and associated records
- **Data Minimization**: Only collect necessary data
- **Audit Logging**: Track all data access and modifications
- **Encryption**: Data encrypted in transit and at rest (configurable)

**Compliance Considerations:**
- Self-hosted deployment keeps data in your jurisdiction
- Configurable data retention policies
- User consent management (application-level)
- Privacy by design architecture

### How do I secure a production deployment?

**Security Checklist:**

1. **Network Security**
```bash
# Use HTTPS only
# Configure firewall
sudo ufw allow 22/tcp    # SSH
sudo ufw allow 443/tcp   # HTTPS
sudo ufw deny 8090/tcp   # Block direct access
```

2. **Configuration Security**
```toml
# Use strong JWT secret
[auth]
jwt_secret = "use-a-long-random-secret-here"

# Enable security headers
[server]
security_headers = true
```

3. **Database Security**
```sql
-- Use dedicated database user
CREATE USER ferritedb_user WITH PASSWORD 'strong_password';
GRANT CONNECT ON DATABASE ferritedb TO ferritedb_user;
```

4. **File Permissions**
```bash
# Secure configuration files
chmod 600 ferritedb.toml
chown ferritedb:ferritedb ferritedb.toml
```

### What about data encryption?

**Encryption Support:**
- **In Transit**: TLS 1.2+ for all HTTP/WebSocket connections
- **At Rest**: Database-level encryption (PostgreSQL TDE, SQLite encryption extensions)
- **Application Level**: Field-level encryption for sensitive data (planned)

**Key Management:**
- Environment variables for secrets
- Integration with cloud key management (AWS KMS, etc.)
- Hardware security modules (HSM) support (planned)

## Comparison with Other Solutions

### FerriteDB vs PocketBase

| Feature | FerriteDB | PocketBase |
|---------|-----------|------------|
| **Language** | Rust | Go |
| **Performance** | Higher | High |
| **Memory Safety** | Yes | No |
| **Database** | SQLite/PostgreSQL | SQLite |
| **Real-time** | WebSocket | Server-Sent Events |
| **Admin UI** | Built-in | Built-in |
| **File Storage** | Local/S3 | Local |
| **Rules Engine** | CEL-like | JavaScript |

### FerriteDB vs Hasura

| Feature | FerriteDB | Hasura |
|---------|-----------|---------|
| **API Type** | REST + WebSocket | GraphQL |
| **Database** | SQLite/PostgreSQL | PostgreSQL |
| **Schema** | Dynamic | Database-first |
| **Deployment** | Single binary | Docker/Cloud |
| **Learning Curve** | Low | Medium |
| **Flexibility** | High | Medium |

### FerriteDB vs Appwrite

| Feature | FerriteDB | Appwrite |
|---------|-----------|----------|
| **Language** | Rust | PHP |
| **Performance** | Higher | Medium |
| **Deployment** | Single binary | Docker Compose |
| **Database** | SQLite/PostgreSQL | MariaDB |
| **Functions** | Planned | Built-in |
| **SDKs** | 3+ languages | 10+ languages |

## Licensing and Commercial Use

### What is the license?

FerriteDB is licensed under the **MIT License**, which means:

- ✅ **Commercial Use**: Use in commercial products
- ✅ **Modification**: Modify the source code
- ✅ **Distribution**: Distribute original or modified versions
- ✅ **Private Use**: Use privately without disclosure
- ❌ **Liability**: No warranty or liability
- ❌ **Trademark**: Cannot use FerriteDB trademarks

### Can I use FerriteDB commercially?

**Yes, absolutely!** The MIT license allows:
- Commercial deployment and usage
- Integration into commercial products
- Selling services built on FerriteDB
- Modification for commercial purposes

**No restrictions on:**
- Number of users or requests
- Revenue generated
- Deployment scale
- Geographic usage

### Is commercial support available?

**Current Support:**
- Community support via GitHub and Discord
- Documentation and guides
- Bug fixes and security updates

**Planned Commercial Support:**
- Priority support and SLA
- Professional services and consulting
- Custom feature development
- Training and onboarding

### Can I contribute to FerriteDB?

**Absolutely!** We welcome contributions:

**Ways to Contribute:**
- Bug reports and feature requests
- Code contributions (Rust, documentation, tests)
- SDK development for other languages
- Documentation improvements
- Community support and advocacy

**Contribution Process:**
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests and documentation
5. Submit a pull request

## Community and Support

### Where can I get help?

**Community Resources:**
- **GitHub Issues**: Bug reports and feature requests
- **GitHub Discussions**: General questions and community chat
- **Discord Server**: Real-time community support
- **Documentation**: Comprehensive guides and API reference

**Response Times:**
- GitHub Issues: 24-48 hours
- Discord: Real-time during business hours
- Security Issues: 24 hours or less

### How can I stay updated?

**Stay Informed:**
- **GitHub Releases**: Subscribe to release notifications
- **Blog**: Development updates and tutorials
- **Twitter**: [@FerriteDB](https://twitter.com/ferritedb) for announcements
- **Newsletter**: Monthly updates and tips

### What's the roadmap?

**Short Term (3-6 months):**
- Additional database support (MySQL)
- Enhanced admin UI
- More SDK languages
- Performance optimizations

**Medium Term (6-12 months):**
- Plugin system
- Advanced analytics
- Multi-tenancy support
- Clustering and HA

**Long Term (12+ months):**
- Machine learning integration
- Advanced workflow engine
- Enterprise features
- Cloud offering

### How can I report security issues?

**Security Contact:**
- Email: security@ferritedb.com
- PGP Key: Available on website
- Response Time: 24 hours or less

**Please DO NOT:**
- Report security issues in public GitHub issues
- Discuss vulnerabilities in public forums
- Attempt to exploit vulnerabilities

**Responsible Disclosure:**
1. Report the issue privately
2. Allow time for investigation and fix
3. Coordinate public disclosure
4. Receive credit in security advisory

---

*This FAQ is regularly updated based on community questions and feedback. If you have a question not covered here, please ask in our GitHub Discussions or Discord server.*