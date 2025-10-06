# FerriteDB Troubleshooting Guide

This guide helps you diagnose and resolve common issues when working with FerriteDB.

## Table of Contents

- [Installation Issues](#installation-issues)
- [Connection Problems](#connection-problems)
- [Authentication Errors](#authentication-errors)
- [Database Issues](#database-issues)
- [Performance Problems](#performance-problems)
- [File Storage Issues](#file-storage-issues)
- [Real-time Connection Issues](#real-time-connection-issues)
- [API Errors](#api-errors)
- [Configuration Problems](#configuration-problems)
- [Logging and Debugging](#logging-and-debugging)

## Installation Issues

### Binary Download Problems

**Problem**: Cannot download or execute FerriteDB binary

**Solutions**:
```bash
# Check if binary is executable
chmod +x ferritedb

# Verify binary integrity
sha256sum ferritedb
# Compare with published checksums

# Check system compatibility
file ferritedb
ldd ferritedb  # Check dependencies on Linux

# Download specific version
curl -L https://github.com/ferritedb/ferritedb/releases/download/v0.1.0/ferritedb-linux-x64 -o ferritedb
```

### Docker Issues

**Problem**: Docker container fails to start

**Solutions**:
```bash
# Check Docker logs
docker logs ferritedb

# Verify image
docker images | grep ferritedb

# Check port conflicts
netstat -tulpn | grep 8090
lsof -i :8090

# Run with debug output
docker run --rm -it ferritedb/ferritedb:latest ferritedb serve --log-level debug

# Check volume permissions
docker run --rm -v ferritedb_data:/data alpine ls -la /data
```

### Compilation Issues

**Problem**: Building from source fails

**Solutions**:
```bash
# Update Rust toolchain
rustup update

# Check Rust version
rustc --version
# Ensure Rust 1.75 or later

# Clean build
cargo clean
cargo build --release

# Check dependencies
cargo tree

# Build with verbose output
cargo build --release --verbose

# Platform-specific issues
cargo build --release --target x86_64-unknown-linux-gnu
```

## Connection Problems

### Cannot Connect to FerriteDB

**Problem**: Client cannot reach FerriteDB server

**Diagnostic Steps**:
```bash
# Check if FerriteDB is running
ps aux | grep ferritedb
systemctl status ferritedb

# Test connectivity
curl http://localhost:8090/api/health
telnet localhost 8090

# Check firewall
sudo ufw status
sudo iptables -L

# Check network configuration
netstat -tulpn | grep 8090
ss -tulpn | grep 8090
```

**Solutions**:
```bash
# Start FerriteDB
systemctl start ferritedb

# Check configuration
cat /etc/ferritedb/ferritedb.toml

# Open firewall port
sudo ufw allow 8090/tcp

# Bind to all interfaces
# In ferritedb.toml:
[server]
host = "0.0.0.0"
port = 8090
```

### Timeout Issues

**Problem**: Requests timeout or take too long

**Solutions**:
```toml
# Increase timeouts in ferritedb.toml
[server]
request_timeout = 60  # Increase from 30

[database]
connection_timeout = 60  # Increase from 30
```

```javascript
// Increase client timeout
const client = new FerriteDB({
  url: 'https://your-instance.com',
  timeout: 30000  // 30 seconds
});
```

### SSL/TLS Issues

**Problem**: HTTPS connection fails

**Diagnostic Steps**:
```bash
# Test SSL certificate
openssl s_client -connect your-domain.com:443 -servername your-domain.com

# Check certificate validity
curl -vI https://your-domain.com/api/health

# Verify certificate chain
ssl-cert-check -c your-domain.com
```

**Solutions**:
```bash
# Renew Let's Encrypt certificate
sudo certbot renew

# Check Nginx SSL configuration
sudo nginx -t
sudo systemctl reload nginx

# Update certificate paths
sudo certbot certificates
```

## Authentication Errors

### JWT Token Issues

**Problem**: "Invalid token" or "Token expired" errors

**Solutions**:
```javascript
// Check token expiration
const payload = JSON.parse(atob(token.split('.')[1]));
console.log('Token expires:', new Date(payload.exp * 1000));

// Refresh token automatically
client.auth.onTokenExpired(async () => {
  const { token } = await client.auth.refresh(refreshToken);
  client.setAuthToken(token);
});

// Handle token refresh in interceptor
client.interceptors.response.use(
  response => response,
  async error => {
    if (error.response?.status === 401) {
      try {
        const { token } = await client.auth.refresh(refreshToken);
        client.setAuthToken(token);
        return client.request(error.config);
      } catch (refreshError) {
        // Redirect to login
        window.location.href = '/login';
      }
    }
    return Promise.reject(error);
  }
);
```

### Password Issues

**Problem**: Login fails with correct credentials

**Diagnostic Steps**:
```bash
# Check user exists in database
sqlite3 /opt/ferritedb/data/ferritedb.db "SELECT email, verified FROM users WHERE email = 'user@example.com';"

# Check password hash
sqlite3 /opt/ferritedb/data/ferritedb.db "SELECT password_hash FROM users WHERE email = 'user@example.com';"
```

**Solutions**:
```bash
# Reset password via admin API
curl -X POST http://localhost:8090/api/admin/users/reset-password \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com", "new_password": "newpassword"}'

# Verify user account
curl -X PATCH http://localhost:8090/api/admin/users/USER_ID \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"verified": true}'
```

## Database Issues

### SQLite Problems

**Problem**: Database corruption or lock errors

**Diagnostic Steps**:
```bash
# Check database integrity
sqlite3 /opt/ferritedb/data/ferritedb.db "PRAGMA integrity_check;"

# Check for locks
lsof /opt/ferritedb/data/ferritedb.db

# Check database size and usage
ls -lh /opt/ferritedb/data/ferritedb.db
sqlite3 /opt/ferritedb/data/ferritedb.db "PRAGMA page_count; PRAGMA page_size;"
```

**Solutions**:
```bash
# Backup and restore database
cp /opt/ferritedb/data/ferritedb.db /opt/ferritedb/data/ferritedb.db.backup
sqlite3 /opt/ferritedb/data/ferritedb.db.backup ".backup /opt/ferritedb/data/ferritedb.db.restored"

# Vacuum database
sqlite3 /opt/ferritedb/data/ferritedb.db "VACUUM;"

# Enable WAL mode for better concurrency
sqlite3 /opt/ferritedb/data/ferritedb.db "PRAGMA journal_mode=WAL;"

# Optimize database
sqlite3 /opt/ferritedb/data/ferritedb.db "PRAGMA optimize;"
```

### PostgreSQL Problems

**Problem**: Connection or performance issues with PostgreSQL

**Diagnostic Steps**:
```bash
# Test PostgreSQL connection
psql "postgresql://user:password@host:5432/database" -c "SELECT version();"

# Check connection limits
psql -c "SELECT * FROM pg_stat_activity;"
psql -c "SHOW max_connections;"

# Check database size
psql -c "SELECT pg_size_pretty(pg_database_size('ferritedb'));"
```

**Solutions**:
```sql
-- Increase connection limits
ALTER SYSTEM SET max_connections = 200;
SELECT pg_reload_conf();

-- Optimize performance
ALTER SYSTEM SET shared_buffers = '256MB';
ALTER SYSTEM SET effective_cache_size = '1GB';
ALTER SYSTEM SET maintenance_work_mem = '64MB';

-- Check slow queries
SELECT query, mean_exec_time, calls 
FROM pg_stat_statements 
ORDER BY mean_exec_time DESC 
LIMIT 10;
```

### Migration Issues

**Problem**: Database migrations fail

**Solutions**:
```bash
# Check migration status
sqlite3 /opt/ferritedb/data/ferritedb.db "SELECT * FROM _migrations;"

# Manual migration rollback
sqlite3 /opt/ferritedb/data/ferritedb.db "DELETE FROM _migrations WHERE version = 'problematic_version';"

# Force migration
ferritedb migrate --force

# Reset database (WARNING: Data loss)
rm /opt/ferritedb/data/ferritedb.db
ferritedb migrate
```

## Performance Problems

### Slow API Responses

**Problem**: API requests are slow

**Diagnostic Steps**:
```bash
# Check system resources
top
htop
iostat -x 1

# Monitor database queries
sqlite3 /opt/ferritedb/data/ferritedb.db "PRAGMA compile_options;"

# Check logs for slow queries
journalctl -u ferritedb -f | grep "slow"

# Profile API endpoints
curl -w "@curl-format.txt" -o /dev/null -s http://localhost:8090/api/collections
```

**Solutions**:
```toml
# Optimize configuration
[database]
max_connections = 50
connection_timeout = 10

[server]
request_timeout = 30
max_request_size = 10485760

# Enable query optimization
[database.sqlite]
journal_mode = "WAL"
synchronous = "NORMAL"
cache_size = 10000
```

### High Memory Usage

**Problem**: FerriteDB uses too much memory

**Diagnostic Steps**:
```bash
# Check memory usage
ps aux | grep ferritedb
pmap $(pgrep ferritedb)

# Monitor memory over time
while true; do
  ps -o pid,vsz,rss,comm -p $(pgrep ferritedb)
  sleep 5
done
```

**Solutions**:
```toml
# Reduce memory usage
[database]
max_connections = 20  # Reduce from default

[server]
max_request_size = 5242880  # 5MB instead of 10MB

# Enable memory limits in systemd
[Service]
MemoryMax=512M
MemoryHigh=400M
```

## File Storage Issues

### Local Storage Problems

**Problem**: File uploads fail or files are corrupted

**Diagnostic Steps**:
```bash
# Check storage directory permissions
ls -la /opt/ferritedb/data/storage/
stat /opt/ferritedb/data/storage/

# Check disk space
df -h /opt/ferritedb/data/

# Check file integrity
find /opt/ferritedb/data/storage/ -type f -exec file {} \;
```

**Solutions**:
```bash
# Fix permissions
sudo chown -R ferritedb:ferritedb /opt/ferritedb/data/storage/
sudo chmod -R 755 /opt/ferritedb/data/storage/

# Clean up orphaned files
find /opt/ferritedb/data/storage/ -type f -mtime +30 -delete

# Check configuration
[storage]
backend = "local"

[storage.local]
base_path = "data/storage"
max_file_size = 10485760  # 10MB
```

### S3 Storage Problems

**Problem**: S3 uploads fail or are slow

**Diagnostic Steps**:
```bash
# Test S3 connectivity
aws s3 ls s3://your-bucket/

# Check credentials
aws sts get-caller-identity

# Test upload speed
aws s3 cp test-file.txt s3://your-bucket/ --debug
```

**Solutions**:
```toml
# Optimize S3 configuration
[storage.s3]
bucket = "your-bucket"
region = "us-east-1"
endpoint = "https://s3.amazonaws.com"  # Custom endpoint if needed
multipart_threshold = 8388608  # 8MB
max_upload_parts = 10000

# Use IAM roles instead of keys
# Remove access_key and secret_key from config
```

## Real-time Connection Issues

### WebSocket Connection Fails

**Problem**: Real-time features don't work

**Diagnostic Steps**:
```bash
# Test WebSocket connection
wscat -c ws://localhost:8090/realtime

# Check proxy configuration
curl -H "Upgrade: websocket" -H "Connection: Upgrade" http://localhost:8090/realtime

# Check firewall
sudo netstat -tulpn | grep 8090
```

**Solutions**:
```nginx
# Fix Nginx WebSocket proxy
location /realtime {
    proxy_pass http://ferritedb_backend;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header Host $host;
    proxy_read_timeout 86400;  # 24 hours
}
```

```javascript
// Handle connection drops
const client = new FerriteDB({
  url: 'wss://your-domain.com',
  reconnect: true,
  reconnectInterval: 5000,
  maxReconnectAttempts: 10
});

client.realtime.on('disconnect', () => {
  console.log('WebSocket disconnected, will retry...');
});
```

## API Errors

### Rate Limiting

**Problem**: "Too Many Requests" (429) errors

**Solutions**:
```javascript
// Implement exponential backoff
async function apiCallWithRetry(apiCall, maxRetries = 3) {
  for (let i = 0; i < maxRetries; i++) {
    try {
      return await apiCall();
    } catch (error) {
      if (error.status === 429) {
        const delay = Math.pow(2, i) * 1000; // Exponential backoff
        await new Promise(resolve => setTimeout(resolve, delay));
        continue;
      }
      throw error;
    }
  }
  throw new Error('Max retries exceeded');
}

// Use rate limiting headers
client.interceptors.response.use(response => {
  const remaining = response.headers['x-ratelimit-remaining'];
  const reset = response.headers['x-ratelimit-reset'];
  
  if (remaining && parseInt(remaining) < 10) {
    console.warn('Rate limit nearly exceeded');
  }
  
  return response;
});
```

### Validation Errors

**Problem**: Request validation fails

**Solutions**:
```javascript
// Validate data before sending
function validatePost(post) {
  const errors = [];
  
  if (!post.title || post.title.length > 200) {
    errors.push('Title is required and must be less than 200 characters');
  }
  
  if (post.email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(post.email)) {
    errors.push('Invalid email format');
  }
  
  return errors;
}

// Handle validation errors
try {
  await client.collection('posts').create(post);
} catch (error) {
  if (error.code === 'VALIDATION_ERROR') {
    console.error('Validation failed:', error.details);
    // Show user-friendly error messages
  }
}
```

## Configuration Problems

### Environment Variables

**Problem**: Configuration not loading correctly

**Diagnostic Steps**:
```bash
# Check environment variables
env | grep FERRITEDB

# Test configuration loading
ferritedb config --show

# Validate configuration file
ferritedb config --validate
```

**Solutions**:
```bash
# Set environment variables properly
export FERRITEDB_AUTH_JWT_SECRET="your-secret-key"
export FERRITEDB_DATABASE_URL="sqlite:data/ferritedb.db"

# Use .env file
cat > .env << EOF
FERRITEDB_AUTH_JWT_SECRET=your-secret-key
FERRITEDB_DATABASE_URL=sqlite:data/ferritedb.db
EOF

# Load .env in systemd service
[Service]
EnvironmentFile=/opt/ferritedb/.env
```

### CORS Issues

**Problem**: Browser requests blocked by CORS

**Solutions**:
```toml
# Configure CORS in ferritedb.toml
[server]
cors_origins = ["https://yourdomain.com", "http://localhost:3000"]
cors_methods = ["GET", "POST", "PUT", "DELETE", "PATCH"]
cors_headers = ["Content-Type", "Authorization"]
cors_credentials = true
```

```nginx
# Or handle CORS in Nginx
location /api/ {
    add_header Access-Control-Allow-Origin "https://yourdomain.com";
    add_header Access-Control-Allow-Methods "GET, POST, PUT, DELETE, PATCH, OPTIONS";
    add_header Access-Control-Allow-Headers "Content-Type, Authorization";
    add_header Access-Control-Allow-Credentials true;
    
    if ($request_method = 'OPTIONS') {
        return 204;
    }
    
    proxy_pass http://ferritedb_backend;
}
```

## Logging and Debugging

### Enable Debug Logging

```toml
# In ferritedb.toml
[logging]
level = "debug"
format = "json"
output = "stdout"

# Or via environment
export FERRITEDB_LOG_LEVEL=debug
export RUST_LOG=ferritedb=debug
```

### Structured Logging

```bash
# View logs with jq for JSON format
journalctl -u ferritedb -f | jq '.'

# Filter specific log levels
journalctl -u ferritedb -f | jq 'select(.level == "ERROR")'

# Search for specific patterns
journalctl -u ferritedb -f | grep "authentication"
```

### Performance Profiling

```bash
# Enable performance metrics
export FERRITEDB_FEATURES_METRICS=true

# View metrics
curl http://localhost:8090/metrics

# Use with Prometheus
# Add to prometheus.yml:
scrape_configs:
  - job_name: 'ferritedb'
    static_configs:
      - targets: ['localhost:8090']
    metrics_path: '/metrics'
```

### Health Monitoring

```bash
# Create health check script
#!/bin/bash
# health-check.sh

HEALTH_URL="http://localhost:8090/api/health"
READINESS_URL="http://localhost:8090/api/readyz"

# Basic health check
if ! curl -f -s "$HEALTH_URL" > /dev/null; then
    echo "CRITICAL: FerriteDB health check failed"
    exit 2
fi

# Readiness check
if ! curl -f -s "$READINESS_URL" > /dev/null; then
    echo "WARNING: FerriteDB not ready"
    exit 1
fi

echo "OK: FerriteDB is healthy and ready"
exit 0
```

### Common Log Messages

| Log Message | Meaning | Action |
|-------------|---------|--------|
| `Database connection failed` | Cannot connect to database | Check database configuration and connectivity |
| `JWT token expired` | Authentication token expired | Refresh token or re-authenticate |
| `Rate limit exceeded` | Too many requests | Implement rate limiting in client |
| `File upload failed` | Storage issue | Check storage configuration and permissions |
| `WebSocket connection lost` | Real-time connection dropped | Check network and proxy configuration |
| `Migration failed` | Database migration error | Check migration logs and database state |

### Getting Help

If you're still experiencing issues:

1. **Check the logs**: Enable debug logging and examine the output
2. **Search documentation**: Look through the [official documentation](https://ferritedb.dev/docs)
3. **Community support**: Join our [Discord server](https://discord.gg/ferritedb)
4. **GitHub issues**: Search existing [issues](https://github.com/ferritedb/ferritedb/issues) or create a new one
5. **Provide details**: Include logs, configuration, and steps to reproduce

### Issue Template

When reporting issues, please include:

```
**Environment:**
- FerriteDB version: 
- Operating system: 
- Database: SQLite/PostgreSQL
- Deployment method: Binary/Docker/Cloud

**Configuration:**
```toml
[relevant config sections]
```

**Steps to reproduce:**
1. 
2. 
3. 

**Expected behavior:**

**Actual behavior:**

**Logs:**
```
[relevant log entries]
```

**Additional context:**
```

---

*This troubleshooting guide is maintained by the FerriteDB community. If you find a solution to a problem not covered here, please contribute by submitting a pull request.*