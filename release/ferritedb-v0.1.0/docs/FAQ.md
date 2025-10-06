# FerriteDB Frequently Asked Questions

This document answers the most commonly asked questions about FerriteDB.

## Table of Contents

- [General Questions](#general-questions)
- [Technical Questions](#technical-questions)
- [Deployment and Operations](#deployment-and-operations)
- [Development and Integration](#development-and-integration)
- [Performance and Scaling](#performance-and-scaling)
- [Security and Compliance](#security-and-compliance)
- [Licensing and Commercial Use](#licensing-and-commercial-use)

## General Questions

### What is FerriteDB?

FerriteDB is a modern, high-performance Backend-as-a-Service (BaaS) built in Rust. It provides a complete backend solution with authentication, dynamic collections, file storage, real-time updates, and a built-in admin interface - all in a single binary.

### How is FerriteDB different from other BaaS solutions?

**Key Differentiators:**
- **Single Binary**: No complex setup or dependencies
- **Rust Performance**: Memory-safe, high-performance core
- **Dynamic Collections**: Schema-less data with optional validation
- **Built-in Admin UI**: No separate admin panel needed
- **Rules Engine**: Flexible, CEL-like access control
- **Real-time by Default**: WebSocket support out of the box
- **Self-hosted**: Full control over your data and infrastructure

### Who should use FerriteDB?

FerriteDB is ideal for:
- **Startups** needing rapid backend development
- **Indie developers** building SaaS applications
- **Teams** wanting self-hosted alternatives to Firebase/Supabase
- **Enterprises** requiring data sovereignty and control
- **Developers** who prefer Rust's performance and safety

### Is FerriteDB production-ready?

Yes, FerriteDB is designed for production use with:
- Comprehensive test coverage
- Battle-tested dependencies (SQLite, PostgreSQL)
- Security best practices
- Performance optimizations
- Monitoring and observability features
- Active maintenance and support

## Technical Questions

### What databases does FerriteDB support?

**Primary Support:**
- **SQLite**: Default, embedded database (recommended for single-instance deployments)
- **PostgreSQL**: Enterprise-grade database (recommended for high-availability deployments)

**Future Roadmap:**
- MySQL/MariaDB support planned
- MongoDB support under consideration

### Can I use my existing database?

FerriteDB manages its own database schema and requires control over the database structure. However, you can:
- Migrate existing data using our migration tools
- Connect to existing PostgreSQL instances
- Use database views to integrate with legacy systems
- Access external databases through custom API endpoints

### What file storage backends are supported?

**Current Support:**
- **Local Filesystem**: Default, suitable for single-server deployments
- **AWS S3**: Production-ready cloud storage
- **S3-Compatible**: MinIO, DigitalOcean Spaces, etc.

**Planned Support:**
- Google Cloud Storage
- Azure Blob Storage
- Custom storage backends via plugins

### How does the rules engine work?

The rules engine uses CEL-like expressions for access control:

```javascript
// Collection-level rules
"list": "user.role == 'admin' || record.published == true"
"create": "user.authenticated == true"
"update": "user.role == 'admin' || record.author == user.id"

// Field-level rules
"email": "user.role == 'admin' || user.id == record.user_id"
```

**Available Context:**
- `user`: Current user information (id, role, email, etc.)
- `record`: Current record being accessed
- `request`: Request information (method, headers, etc.)
- `collection`: Collection metadata

### Can I extend FerriteDB with custom functionality?

**Current Options:**
- Custom rules for business logic
- Webhooks for external integrations
- Custom middleware (planned)
- Plugin system (roadmap)

**Workarounds:**
- Proxy requests through your application
- Use FerriteDB as a data layer with custom API layer
- Contribute features to the open-source project

## Deployment and Operations

### What are the system requirements?

**Minimum Requirements:**
- 1 vCPU, 512MB RAM, 1GB storage
- Linux, macOS, or Windows
- No additional dependencies

**Production Recommendations:**
- 2+ vCPUs, 2GB+ RAM, 10GB+ SSD storage
- Linux (Ubuntu 20.04+ or CentOS 8+)
- Reverse proxy (Nginx/Apache)
- SSL certificate

### How do I deploy FerriteDB?

**Deployment Options:**
1. **Single Binary**: Download and run directly
2. **Docker**: Use official Docker images
3. **Docker Compose**: Multi-service setup with proxy
4. **Kubernetes**: Production-grade orchestration
5. **Cloud Platforms**: Railway, Fly.io, AWS ECS, Google Cloud Run

See our [Deployment Guide](DEPLOYMENT.md) for detailed instructions.

### How do I backup my data?

**Database Backup:**
```bash
# SQLite
sqlite3 ferritedb.db ".backup backup.db"

# PostgreSQL
pg_dump database_url > backup.sql
```

**File Storage Backup:**
```bash
# Local files
rsync -av data/storage/ backup/storage/

# S3 files
aws s3 sync s3://your-bucket/ backup/s3/
```

**Automated Backups:**
- Use cron jobs for regular backups
- Implement backup rotation policies
- Store backups in separate locations
- Test restore procedures regularly

### How do I monitor FerriteDB?

**Built-in Monitoring:**
- Health check endpoints (`/api/health`, `/api/readyz`)
- Prometheus metrics (`/metrics`)
- Structured logging (JSON format)
- Admin dashboard statistics

**External Monitoring:**
- Prometheus + Grafana for metrics
- ELK stack for log aggregation
- Uptime monitoring services
- Custom health check scripts

### Can FerriteDB scale horizontally?

**Current Limitations:**
- SQLite is single-instance only
- File storage needs shared backend (S3)
- WebSocket connections are sticky

**Scaling Strategies:**
- Use PostgreSQL for multi-instance deployments
- Load balance with session affinity for WebSockets
- Use S3 or shared storage for files
- Implement read replicas (planned feature)

## Development and Integration

### What SDKs are available?

**Official SDKs:**
- **JavaScript/TypeScript**: `@ferritedb/sdk-js` (Stable)
- **Rust**: `ferritedb-sdk` (Stable)
- **Python**: `ferritedb-python` (Beta)
- **Go**: `ferritedb-go` (Beta)

**Planned SDKs:**
- PHP, C#, Java, Swift

See our [SDK Guide](SDK_GUIDE.md) for detailed usage.

### How do I integrate with my existing authentication?

**Options:**
1. **Use FerriteDB Auth**: Migrate users to FerriteDB
2. **Custom JWT**: Generate JWT tokens from your auth system
3. **API Keys**: Use server-to-server authentication
4. **Proxy Pattern**: Route through your application

**Custom JWT Example:**
```javascript
// Generate JWT with your secret
const token = jwt.sign({
  sub: user.id,
  email: user.email,
  role: user.role,
  exp: Math.floor(Date.now() / 1000) + 3600
}, process.env.FERRITEDB_JWT_SECRET);

// Use with FerriteDB client
client.setAuthToken(token);
```

### Can I use FerriteDB with my frontend framework?

Yes! FerriteDB works with any frontend framework:

**React/Next.js:**
```javascript
import { FerriteDB } from '@ferritedb/sdk-js';

const client = new FerriteDB({
  url: process.env.NEXT_PUBLIC_FERRITEDB_URL
});
```

**Vue/Nuxt:**
```javascript
// plugins/ferritedb.js
import { FerriteDB } from '@ferritedb/sdk-js';

export default ({ $config }, inject) => {
  const client = new FerriteDB({
    url: $config.ferritedbUrl
  });
  inject('ferritedb', client);
};
```

**Svelte/SvelteKit:**
```javascript
// lib/ferritedb.js
import { FerriteDB } from '@ferritedb/sdk-js';
import { PUBLIC_FERRITEDB_URL } from '$env/static/public';

export const client = new FerriteDB({
  url: PUBLIC_FERRITEDB_URL
});
```

### How do I handle real-time updates?

**WebSocket Connection:**
```javascript
// Subscribe to collection changes
const unsubscribe = client.realtime.subscribe('posts', (event) => {
  switch (event.type) {
    case 'record_created':
      // Handle new record
      break;
    case 'record_updated':
      // Handle updated record
      break;
    case 'record_deleted':
      // Handle deleted record
      break;
  }
});

// Clean up subscription
unsubscribe();
```

**React Hook Example:**
```javascript
function useRealtimeCollection(collection, filter) {
  const [records, setRecords] = useState([]);
  
  useEffect(() => {
    // Initial fetch
    client.collection(collection).list({ filter }).then(setRecords);
    
    // Subscribe to changes
    return client.realtime.subscribe(collection, (event) => {
      if (event.type === 'record_created') {
        setRecords(prev => [event.record, ...prev]);
      }
      // Handle other events...
    }, { filter });
  }, [collection, filter]);
  
  return records;
}
```

## Performance and Scaling

### How fast is FerriteDB?

**Benchmarks** (on modern hardware):
- **Simple queries**: 1000+ requests/second
- **Complex queries**: 500+ requests/second
- **File uploads**: 100+ MB/second
- **WebSocket messages**: 10,000+ messages/second
- **Memory usage**: 50-200MB typical

**Performance factors:**
- Database choice (SQLite vs PostgreSQL)
- Hardware specifications
- Network latency
- Query complexity
- Concurrent connections

### How do I optimize performance?

**Database Optimization:**
```toml
# SQLite optimizations
[database]
url = "sqlite:data/ferritedb.db?cache=shared&_journal_mode=WAL&_synchronous=NORMAL"
max_connections = 20
connection_timeout = 10

# PostgreSQL optimizations
[database]
url = "postgresql://user:pass@host/db?sslmode=require"
max_connections = 50
```

**Application Optimization:**
- Use pagination for large datasets
- Implement client-side caching
- Optimize database queries
- Use CDN for file storage
- Enable compression

**Infrastructure Optimization:**
- Use SSD storage
- Increase available RAM
- Use connection pooling
- Implement load balancing
- Use reverse proxy caching

### What are the scaling limits?

**Single Instance Limits:**
- **SQLite**: ~1TB database, 1000 concurrent connections
- **PostgreSQL**: Limited by hardware and configuration
- **Files**: Limited by storage backend
- **Memory**: ~1GB per 10,000 concurrent connections

**Multi-Instance Scaling:**
- Requires PostgreSQL backend
- Shared file storage (S3)
- Load balancer with session affinity
- Horizontal scaling possible

### How do I handle high traffic?

**Strategies:**
1. **Vertical Scaling**: Increase server resources
2. **Horizontal Scaling**: Multiple FerriteDB instances
3. **Caching**: Redis/Memcached for frequently accessed data
4. **CDN**: CloudFlare/AWS CloudFront for static assets
5. **Database Optimization**: Indexes, query optimization
6. **Rate Limiting**: Protect against abuse

## Security and Compliance

### Is FerriteDB secure?

**Security Features:**
- JWT-based authentication with secure defaults
- Argon2 password hashing
- HTTPS/TLS encryption
- CORS protection
- Rate limiting
- Input validation and sanitization
- SQL injection prevention
- XSS protection headers

**Security Best Practices:**
- Use strong JWT secrets
- Enable HTTPS in production
- Implement proper firewall rules
- Regular security updates
- Audit logging enabled
- Principle of least privilege

### How do I secure my FerriteDB deployment?

**Configuration Security:**
```toml
[auth]
jwt_secret = "use-a-strong-random-secret"
token_ttl = 900  # 15 minutes
password_min_length = 12

[server]
cors_origins = ["https://yourdomain.com"]  # Specific origins only
rate_limit_requests_per_minute = 60
```

**Infrastructure Security:**
- Use HTTPS with valid certificates
- Firewall rules (only allow necessary ports)
- Regular security updates
- Secure file permissions
- Network segmentation
- VPN access for admin functions

### Is FerriteDB GDPR compliant?

FerriteDB provides tools for GDPR compliance:

**Data Protection Features:**
- User data export APIs
- Data deletion capabilities
- Audit logging for compliance
- Encryption at rest and in transit
- Data retention policies (configurable)

**Compliance Responsibilities:**
- You control data processing purposes
- You implement privacy policies
- You handle consent management
- You configure retention policies
- You manage data subject requests

### Can I audit FerriteDB access?

**Audit Logging:**
```toml
[features]
audit_logging = true

[logging]
level = "info"
format = "json"
```

**Audit Information:**
- User authentication events
- Data access and modifications
- Admin actions
- API requests and responses
- File upload/download events
- Configuration changes

**Log Analysis:**
- Export logs to SIEM systems
- Use log aggregation tools (ELK stack)
- Set up alerting for suspicious activity
- Regular audit log reviews

## Licensing and Commercial Use

### What license does FerriteDB use?

FerriteDB is released under the **MIT License**, which means:
- ✅ Commercial use allowed
- ✅ Modification allowed
- ✅ Distribution allowed
- ✅ Private use allowed
- ❌ No warranty provided
- ❌ No liability accepted

### Can I use FerriteDB commercially?

**Yes!** The MIT license allows commercial use without restrictions:
- Build and sell applications using FerriteDB
- Offer FerriteDB as part of your service
- Modify FerriteDB for your needs
- No licensing fees or royalties

### Do I need to contribute back changes?

**No requirement**, but contributions are welcome:
- MIT license doesn't require sharing modifications
- Contributing helps the community
- Shared maintenance burden
- Faster bug fixes and features
- Recognition in the project

### Is there commercial support available?

**Community Support:**
- GitHub issues and discussions
- Discord community chat
- Documentation and guides
- Community-contributed solutions

**Commercial Support:**
- Professional support contracts available
- Custom development services
- Training and consulting
- Priority bug fixes and features
- Contact: support@ferritedb.dev

### Can I get a different license?

For enterprise customers requiring different licensing terms:
- Custom licensing agreements available
- Proprietary licensing options
- Indemnification and warranties
- Service level agreements (SLAs)
- Contact: enterprise@ferritedb.dev

---

## Still Have Questions?

If your question isn't answered here:

1. **Search Documentation**: Check our [comprehensive docs](https://ferritedb.dev/docs)
2. **Community Discord**: Join our [Discord server](https://discord.gg/ferritedb)
3. **GitHub Discussions**: Browse [GitHub discussions](https://github.com/ferritedb/ferritedb/discussions)
4. **Stack Overflow**: Tag questions with `ferritedb`
5. **Contact Support**: Email support@ferritedb.dev

### Contributing to FAQ

Found an error or have a suggestion? This FAQ is community-maintained:
- Submit issues on [GitHub](https://github.com/ferritedb/ferritedb/issues)
- Contribute improvements via pull requests
- Share your questions in Discord for future FAQ additions

---

*Last updated: October 2025 | Version: 1.0*