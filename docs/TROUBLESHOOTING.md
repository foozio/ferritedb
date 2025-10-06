# FerriteDB Troubleshooting Guide

This comprehensive guide helps you diagnose and resolve common issues with FerriteDB deployment, configuration, and usage.

## Table of Contents

- [Quick Diagnostics](#quick-diagnostics)
- [Installation Issues](#installation-issues)
- [Configuration Problems](#configuration-problems)
- [Database Issues](#database-issues)
- [Authentication Problems](#authentication-problems)
- [API and Network Issues](#api-and-network-issues)
- [Performance Problems](#performance-problems)
- [File Storage Issues](#file-storage-issues)
- [Real-time Connection Issues](#real-time-connection-issues)
- [Docker and Container Issues](#docker-and-container-issues)
- [Development Environment Issues](#development-environment-issues)
- [Production Deployment Issues](#production-deployment-issues)
- [Monitoring and Logging](#monitoring-and-logging)
- [Getting Help](#getting-help)

## Quick Diagnostics

### Health Check Commands

```bash
# Basic health check
curl -f http://localhost:8090/api/healthz

# Detailed readiness check
curl -f http://localhost:8090/api/readyz

# Check with verbose output
curl -v http://localhost:8090/api/healthz

# Test with authentication
curl -H "Authorization: Bearer YOUR_TOKEN" http://localhost:8090/api/auth/me
```

### Log Analysis

```bash
# View FerriteDB logs
docker logs ferritedb

# Follow logs in real-time
docker logs -f ferritedb

# View last 100 lines
docker logs --tail 100 ferritedb

# Filter logs by level
docker logs ferritedb 2>&1 | grep ERROR

# For systemd service
journalctl -u ferritedb -f
```

### System Information

```bash
# Check system resources
free -h
df -h
top -p $(pgrep ferritedb)

# Check network connectivity
netstat -tlnp | grep 8090
ss -tlnp | grep 8090

# Check file permissions
ls -la /path/to/ferritedb/data/
```

## Installation Issues

### Binary Installation Problems

#### Issue: "Permission denied" when running FerriteDB
```bash
# Solution: Fix file permissions
chmod +x /usr/local/bin/ferritedb

# Or if installed locally
chmod +x ./ferritedb
```

#### Issue: "Command not found"
```bash
# Solution: Add to PATH or use full path
export PATH=$PATH:/usr/local/bin

# Or create symlink
sudo ln -s /path/to/ferritedb /usr/local/bin/ferritedb
```

#### Issue: "Library not found" errors
```bash
# Check dependencies (Linux)
ldd /usr/local/bin/ferritedb

# Install missing libraries (Ubuntu/Debian)
sudo apt-get update
sudo apt-get install libc6 libssl3

# For CentOS/RHEL
sudo yum install glibc openssl-libs
```

### Rust Compilation Issues

#### Issue: Compilation fails with "linker not found"
```bash
# Install build tools (Ubuntu/Debian)
sudo apt-get install build-essential

# For CentOS/RHEL
sudo yum groupinstall "Development Tools"

# For macOS
xcode-select --install
```

#### Issue: "failed to run custom build command for sqlx"
```bash
# Install SQLite development headers
sudo apt-get install libsqlite3-dev

# For CentOS/RHEL
sudo yum install sqlite-devel

# For macOS
brew install sqlite
```

#### Issue: Out of memory during compilation
```bash
# Reduce parallel jobs
cargo build --jobs 1

# Or increase swap space
sudo fallocate -l 2G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile
```

## Configuration Problems

### Configuration File Issues

#### Issue: "Configuration file not found"
```bash
# Check file exists
ls -la ferritedb.toml

# Use absolute path
ferritedb serve --config /full/path/to/ferritedb.toml

# Check current directory
pwd
```

#### Issue: "Invalid configuration format"
```toml
# Common TOML syntax errors:

# ❌ Wrong: Missing quotes for strings with spaces
title = My App Name

# ✅ Correct: Quoted strings
title = "My App Name"

# ❌ Wrong: Invalid section syntax
[server
host = "localhost"

# ✅ Correct: Proper section syntax
[server]
host = "localhost"

# ❌ Wrong: Duplicate keys
port = 8090
port = 3000

# ✅ Correct: Single key definition
port = 8090
```

#### Issue: Environment variables not working
```bash
# Check environment variable format
export FERRITEDB_SERVER_HOST="0.0.0.0"
export FERRITEDB_SERVER_PORT="8090"

# Verify variables are set
env | grep FERRITEDB

# Debug configuration loading
RUST_LOG=ferritedb=debug ferritedb serve --config ferritedb.toml
```

### Database Configuration Issues

#### Issue: "Database connection failed"
```toml
# Check database URL format
[database]
# ✅ Correct SQLite URL
url = "sqlite:data/ferritedb.db"

# ✅ Correct PostgreSQL URL
url = "postgresql://user:password@localhost:5432/ferritedb"

# ❌ Wrong: Missing protocol
url = "data/ferritedb.db"
```

#### Issue: "Permission denied" for SQLite database
```bash
# Check file permissions
ls -la data/ferritedb.db

# Fix permissions
chmod 644 data/ferritedb.db
chown ferritedb:ferritedb data/ferritedb.db

# Check directory permissions
chmod 755 data/
```

## Database Issues

### SQLite Problems

#### Issue: "Database is locked"
```bash
# Check for other processes using the database
lsof data/ferritedb.db

# Kill processes if safe to do so
kill -9 PID

# Check for .db-wal and .db-shm files
ls -la data/ferritedb.db*

# Remove if FerriteDB is not running
rm data/ferritedb.db-wal data/ferritedb.db-shm
```

#### Issue: "Disk I/O error"
```bash
# Check disk space
df -h

# Check disk health
sudo fsck /dev/sda1

# Check file system permissions
ls -la data/

# Move database to different location if needed
mv data/ferritedb.db /tmp/
# Update config to point to new location
```

#### Issue: "Database corruption"
```bash
# Check database integrity
sqlite3 data/ferritedb.db "PRAGMA integrity_check;"

# Attempt repair
sqlite3 data/ferritedb.db "PRAGMA integrity_check;"
sqlite3 data/ferritedb.db ".recover" | sqlite3 recovered.db

# Restore from backup
cp backup/ferritedb.db data/ferritedb.db
```

### PostgreSQL Problems

#### Issue: "Connection refused"
```bash
# Check PostgreSQL is running
sudo systemctl status postgresql

# Start PostgreSQL
sudo systemctl start postgresql

# Check connection
psql -h localhost -U ferritedb_user -d ferritedb

# Check PostgreSQL logs
sudo tail -f /var/log/postgresql/postgresql-*.log
```

#### Issue: "Authentication failed"
```sql
-- Check user exists
SELECT * FROM pg_user WHERE usename = 'ferritedb_user';

-- Reset password
ALTER USER ferritedb_user PASSWORD 'new_password';

-- Check permissions
GRANT ALL PRIVILEGES ON DATABASE ferritedb TO ferritedb_user;
```

#### Issue: "Too many connections"
```sql
-- Check current connections
SELECT count(*) FROM pg_stat_activity;

-- Check max connections
SHOW max_connections;

-- Kill idle connections
SELECT pg_terminate_backend(pid) 
FROM pg_stat_activity 
WHERE state = 'idle' AND state_change < now() - interval '5 minutes';
```

### Migration Issues

#### Issue: "Migration failed"
```bash
# Check migration status
sqlx migrate info --database-url sqlite:data/ferritedb.db

# Revert last migration
sqlx migrate revert --database-url sqlite:data/ferritedb.db

# Force migration
sqlx migrate run --database-url sqlite:data/ferritedb.db --ignore-missing

# Manual migration
sqlite3 data/ferritedb.db < migrations/001_initial.sql
```

## Authentication Problems

### JWT Token Issues

#### Issue: "Invalid token" errors
```bash
# Check token expiration
# Decode JWT token (use online JWT decoder or)
echo "YOUR_TOKEN" | cut -d. -f2 | base64 -d

# Check server time vs client time
date
curl -I http://localhost:8090/api/health

# Verify JWT secret in config
grep jwt_secret ferritedb.toml
```

#### Issue: "Token expired" frequently
```toml
# Increase token TTL in config
[auth]
token_ttl = 7200  # 2 hours instead of 1 hour
refresh_ttl = 172800  # 48 hours instead of 24 hours
```

#### Issue: "Authentication header missing"
```bash
# Check request format
curl -H "Authorization: Bearer YOUR_TOKEN" http://localhost:8090/api/auth/me

# ❌ Wrong header format
curl -H "Auth: YOUR_TOKEN" http://localhost:8090/api/auth/me

# ✅ Correct header format
curl -H "Authorization: Bearer YOUR_TOKEN" http://localhost:8090/api/auth/me
```

### Password Issues

#### Issue: "Password hashing failed"
```toml
# Check Argon2 parameters in config
[auth]
argon2_memory = 65536      # Reduce if low memory
argon2_iterations = 3      # Reduce if too slow
argon2_parallelism = 4     # Reduce if limited CPU
```

#### Issue: "Password too weak"
```toml
# Check password requirements
[auth]
password_min_length = 8
password_require_uppercase = true
password_require_lowercase = true
password_require_numbers = true
password_require_symbols = true
```

## API and Network Issues

### Connection Problems

#### Issue: "Connection refused"
```bash
# Check if FerriteDB is running
ps aux | grep ferritedb

# Check port binding
netstat -tlnp | grep 8090

# Check firewall
sudo ufw status
sudo iptables -L

# Test local connection
curl http://localhost:8090/api/health

# Test external connection
curl http://YOUR_SERVER_IP:8090/api/health
```

#### Issue: "Timeout errors"
```toml
# Increase timeout in config
[server]
request_timeout = 60  # Increase from 30 seconds

# Check network latency
ping YOUR_SERVER_IP
traceroute YOUR_SERVER_IP
```

#### Issue: "CORS errors"
```toml
# Fix CORS configuration
[server]
cors_origins = ["http://localhost:3000", "https://yourdomain.com"]
cors_methods = ["GET", "POST", "PUT", "DELETE", "OPTIONS"]
cors_headers = ["Content-Type", "Authorization"]
```

### SSL/TLS Issues

#### Issue: "SSL certificate errors"
```bash
# Check certificate validity
openssl x509 -in cert.pem -text -noout

# Test SSL connection
openssl s_client -connect yourdomain.com:443

# Check certificate chain
curl -vI https://yourdomain.com
```

#### Issue: "Mixed content errors"
```nginx
# Ensure all traffic is HTTPS
server {
    listen 80;
    server_name yourdomain.com;
    return 301 https://$server_name$request_uri;
}
```

### Rate Limiting Issues

#### Issue: "Too many requests"
```toml
# Adjust rate limiting
[server]
rate_limit_requests = 1000  # Increase limit
rate_limit_window = 3600    # Per hour
```

```bash
# Check current rate limit status
curl -I http://localhost:8090/api/health
# Look for X-RateLimit-* headers
```

## Performance Problems

### Slow Response Times

#### Issue: Database queries are slow
```sql
-- Enable query logging (PostgreSQL)
SET log_statement = 'all';
SET log_min_duration_statement = 1000; -- Log queries > 1 second

-- Check slow queries
SELECT query, mean_time, calls 
FROM pg_stat_statements 
ORDER BY mean_time DESC 
LIMIT 10;

-- Add indexes for common queries
CREATE INDEX idx_records_collection ON records(collection);
CREATE INDEX idx_records_created_at ON records(created_at);
```

#### Issue: High memory usage
```bash
# Check memory usage
free -h
ps aux --sort=-%mem | head

# Reduce connection pool size
[database]
max_connections = 5  # Reduce from 10

# Enable memory profiling
RUST_LOG=debug ferritedb serve --config ferritedb.toml
```

#### Issue: High CPU usage
```bash
# Check CPU usage
top -p $(pgrep ferritedb)

# Profile CPU usage
perf record -g ./ferritedb serve --config ferritedb.toml
perf report

# Reduce concurrent requests
[server]
max_concurrent_requests = 100  # Add limit
```

### File Upload Issues

#### Issue: "File too large" errors
```toml
# Increase file size limits
[server]
max_request_size = 52428800  # 50MB

[storage.local]
max_file_size = 52428800  # 50MB
```

#### Issue: Slow file uploads
```toml
# Optimize storage configuration
[storage.local]
buffer_size = 8192  # Increase buffer size
use_sendfile = true  # Enable sendfile optimization
```

## File Storage Issues

### Local Storage Problems

#### Issue: "Permission denied" for file operations
```bash
# Check storage directory permissions
ls -la data/files/

# Fix permissions
chmod 755 data/files/
chown -R ferritedb:ferritedb data/files/

# Check disk space
df -h data/
```

#### Issue: "File not found" errors
```bash
# Check file exists
ls -la data/files/path/to/file

# Check symlinks
ls -laL data/files/path/to/file

# Verify storage path in config
grep -A5 "\[storage.local\]" ferritedb.toml
```

### S3 Storage Problems

#### Issue: "Access denied" for S3 operations
```bash
# Check AWS credentials
aws sts get-caller-identity

# Test S3 access
aws s3 ls s3://your-bucket/

# Check IAM permissions
aws iam get-user-policy --user-name your-user --policy-name your-policy
```

#### Issue: "Bucket not found"
```toml
# Check S3 configuration
[storage.s3]
bucket = "your-bucket-name"  # Verify bucket name
region = "us-east-1"         # Verify region
endpoint = "https://s3.amazonaws.com"  # For custom endpoints
```

#### Issue: S3 connection timeouts
```toml
# Increase S3 timeouts
[storage.s3]
timeout = 60
retry_attempts = 3
```

## Real-time Connection Issues

### WebSocket Problems

#### Issue: "WebSocket connection failed"
```bash
# Test WebSocket connection
wscat -c ws://localhost:8090/realtime

# Check WebSocket headers
curl -i -N -H "Connection: Upgrade" \
     -H "Upgrade: websocket" \
     -H "Sec-WebSocket-Version: 13" \
     -H "Sec-WebSocket-Key: SGVsbG8sIHdvcmxkIQ==" \
     http://localhost:8090/realtime
```

#### Issue: "WebSocket disconnects frequently"
```toml
# Increase WebSocket timeouts
[realtime]
ping_interval = 30     # Send ping every 30 seconds
pong_timeout = 10      # Wait 10 seconds for pong
max_connections = 1000 # Increase connection limit
```

#### Issue: "Messages not received"
```javascript
// Check WebSocket event handling
ws.onopen = () => console.log('Connected');
ws.onmessage = (event) => console.log('Message:', event.data);
ws.onerror = (error) => console.error('Error:', error);
ws.onclose = (event) => console.log('Closed:', event.code, event.reason);

// Verify subscription format
ws.send(JSON.stringify({
  type: 'subscribe',
  collection: 'posts',
  filter: 'published=true'
}));
```

### Proxy Issues with WebSockets

#### Issue: WebSocket through reverse proxy
```nginx
# Nginx WebSocket configuration
location /realtime {
    proxy_pass http://ferritedb_backend;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    
    # Increase timeouts for WebSocket
    proxy_read_timeout 86400;
    proxy_send_timeout 86400;
}
```

## Docker and Container Issues

### Container Startup Problems

#### Issue: "Container exits immediately"
```bash
# Check container logs
docker logs ferritedb

# Run container interactively
docker run -it --rm ferritedb/ferritedb:latest /bin/sh

# Check container health
docker inspect ferritedb | grep -A5 Health
```

#### Issue: "Port already in use"
```bash
# Check what's using the port
lsof -i :8090
netstat -tlnp | grep 8090

# Kill process using port
kill -9 PID

# Use different port
docker run -p 8091:8090 ferritedb/ferritedb:latest
```

#### Issue: "Volume mount issues"
```bash
# Check volume permissions
ls -la /host/path/to/data

# Fix SELinux context (if applicable)
sudo chcon -Rt svirt_sandbox_file_t /host/path/to/data

# Use named volume instead
docker volume create ferritedb_data
docker run -v ferritedb_data:/app/data ferritedb/ferritedb:latest
```

### Docker Compose Issues

#### Issue: "Service dependencies not ready"
```yaml
# Add health checks and depends_on
version: '3.8'
services:
  postgres:
    image: postgres:14
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U postgres"]
      interval: 30s
      timeout: 10s
      retries: 3
  
  ferritedb:
    image: ferritedb/ferritedb:latest
    depends_on:
      postgres:
        condition: service_healthy
```

#### Issue: "Environment variables not passed"
```yaml
# Check environment variable syntax
services:
  ferritedb:
    environment:
      - FERRITEDB_AUTH_JWT_SECRET=${JWT_SECRET}
      # Or
      FERRITEDB_AUTH_JWT_SECRET: ${JWT_SECRET}
    
    # Load from .env file
    env_file:
      - .env
```

## Development Environment Issues

### Rust Development Problems

#### Issue: "Cargo build fails"
```bash
# Clean build cache
cargo clean

# Update dependencies
cargo update

# Check for conflicting versions
cargo tree --duplicates

# Build with verbose output
cargo build --verbose
```

#### Issue: "Tests fail"
```bash
# Run tests with output
cargo test -- --nocapture

# Run specific test
cargo test test_name

# Run tests serially (avoid conflicts)
cargo test -- --test-threads=1

# Set test database
export DATABASE_URL=sqlite::memory:
cargo test
```

#### Issue: "IDE/Editor issues"
```bash
# Restart rust-analyzer
# In VS Code: Ctrl+Shift+P -> "Rust Analyzer: Restart Server"

# Check rust-analyzer logs
# In VS Code: View -> Output -> Select "Rust Analyzer Language Server"

# Update rust-analyzer
rustup component add rust-analyzer
```

### Hot Reload Issues

#### Issue: "Changes not reflected"
```bash
# Use cargo-watch for auto-reload
cargo install cargo-watch
cargo watch -x 'run -- serve --config ferritedb.dev.toml'

# Clear target directory
rm -rf target/
cargo build
```

## Production Deployment Issues

### Load Balancer Problems

#### Issue: "Health checks failing"
```nginx
# Configure proper health check
upstream ferritedb_backend {
    server ferritedb1:8090 max_fails=3 fail_timeout=30s;
    server ferritedb2:8090 max_fails=3 fail_timeout=30s;
}

# Health check location
location /health {
    access_log off;
    proxy_pass http://ferritedb_backend/api/health;
    proxy_connect_timeout 5s;
    proxy_read_timeout 5s;
}
```

#### Issue: "Session stickiness problems"
```nginx
# Add session stickiness if needed
upstream ferritedb_backend {
    ip_hash;  # Route based on client IP
    server ferritedb1:8090;
    server ferritedb2:8090;
}
```

### Kubernetes Issues

#### Issue: "Pod crashes with OOMKilled"
```yaml
# Increase memory limits
resources:
  limits:
    memory: "1Gi"
  requests:
    memory: "512Mi"

# Add memory monitoring
kubectl top pods
kubectl describe pod ferritedb-pod
```

#### Issue: "Service not accessible"
```bash
# Check service endpoints
kubectl get endpoints ferritedb-service

# Check pod labels and selectors
kubectl get pods --show-labels
kubectl describe service ferritedb-service

# Test internal connectivity
kubectl exec -it test-pod -- curl http://ferritedb-service/api/health
```

### SSL Certificate Issues

#### Issue: "Let's Encrypt certificate renewal fails"
```bash
# Check certificate status
certbot certificates

# Renew manually
certbot renew --dry-run
certbot renew --force-renewal

# Check nginx configuration
nginx -t
systemctl reload nginx
```

## Monitoring and Logging

### Log Analysis

#### Enable Debug Logging
```bash
# Set log level
export RUST_LOG=debug
ferritedb serve --config ferritedb.toml

# Specific module logging
export RUST_LOG=ferritedb=debug,sqlx=info
```

#### Structured Logging
```toml
# Configure structured logging
[logging]
level = "info"
format = "json"
output = "stdout"
```

### Metrics Collection

#### Issue: "Metrics not available"
```toml
# Enable metrics in config
[features]
metrics = true

# Check metrics endpoint
curl http://localhost:8090/metrics
```

#### Issue: "Prometheus scraping fails"
```yaml
# Check Prometheus configuration
scrape_configs:
  - job_name: 'ferritedb'
    static_configs:
      - targets: ['localhost:8090']
    metrics_path: /metrics
    scrape_interval: 30s
```

### Performance Monitoring

```bash
# Monitor system resources
htop
iotop
nethogs

# Monitor database performance
# For PostgreSQL
SELECT * FROM pg_stat_activity;
SELECT * FROM pg_stat_statements ORDER BY total_time DESC;

# For SQLite
PRAGMA compile_options;
PRAGMA cache_size;
```

## Getting Help

### Diagnostic Information to Collect

When seeking help, please provide:

1. **Version Information**
```bash
ferritedb --version
rustc --version
```

2. **Configuration** (sanitized)
```bash
# Remove sensitive information like passwords and secrets
cat ferritedb.toml | sed 's/password = .*/password = "***"/'
```

3. **Error Logs**
```bash
# Last 100 lines of logs
docker logs --tail 100 ferritedb 2>&1
```

4. **System Information**
```bash
uname -a
free -h
df -h
```

5. **Network Information**
```bash
netstat -tlnp | grep 8090
curl -v http://localhost:8090/api/health
```

### Community Resources

- **GitHub Issues**: [https://github.com/foozio/ferritedb/issues](https://github.com/foozio/ferritedb/issues)
- **Discussions**: [https://github.com/foozio/ferritedb/discussions](https://github.com/foozio/ferritedb/discussions)
- **Discord**: [Join our Discord server](https://discord.gg/ferritedb)
- **Documentation**: [https://docs.ferritedb.com](https://docs.ferritedb.com)

### Creating Bug Reports

When creating a bug report, include:

1. **Clear description** of the issue
2. **Steps to reproduce** the problem
3. **Expected behavior** vs actual behavior
4. **Environment details** (OS, Docker version, etc.)
5. **Configuration files** (sanitized)
6. **Error logs** and stack traces
7. **Minimal reproduction case** if possible

### Performance Issues

For performance issues, also include:

1. **System specifications** (CPU, RAM, storage)
2. **Load characteristics** (requests/second, data size)
3. **Performance metrics** (response times, resource usage)
4. **Database query patterns**
5. **Network latency** measurements

---

*This troubleshooting guide is continuously updated based on community feedback and common issues. If you encounter a problem not covered here, please let us know so we can improve this guide.*