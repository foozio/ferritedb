# Operations Guide

This guide covers operational aspects of running FerriteDB in production, including deployment, monitoring, backup strategies, and maintenance procedures.

## Table of Contents

- [Deployment](#deployment)
- [Configuration Management](#configuration-management)
- [Monitoring and Observability](#monitoring-and-observability)
- [Backup and Recovery](#backup-and-recovery)
- [Security Operations](#security-operations)
- [Performance Tuning](#performance-tuning)
- [Troubleshooting](#troubleshooting)
- [Maintenance](#maintenance)

## Deployment

### Production Deployment Options

#### 1. Docker Deployment (Recommended)

```bash
# Pull the latest image
docker pull ferritedb/ferritedb:latest

# Run with docker-compose
docker-compose up -d

# Or run directly
docker run -d \
  --name ferritedb \
  -p 8090:8090 \
  -v ferritedb_data:/app/data \
  -v ./ferritedb.toml:/app/ferritedb.toml:ro \
  -e FERRITEDB_AUTH_JWT_SECRET="your-secure-secret" \
  ferritedb/ferritedb:latest
```

#### 2. Binary Deployment

```bash
# Download and install
curl -L https://github.com/ferritedb/ferritedb/releases/latest/download/ferritedb-linux-x86_64.tar.gz | tar xz
sudo mv ferritedb /usr/local/bin/

# Create service user
sudo useradd --system --home /var/lib/ferritedb --shell /bin/false ferritedb

# Create directories
sudo mkdir -p /var/lib/ferritedb/{data,config,logs}
sudo chown -R ferritedb:ferritedb /var/lib/ferritedb

# Create systemd service
sudo tee /etc/systemd/system/ferritedb.service << 'EOF'
[Unit]
Description=FerriteDB Backend Service
After=network.target
Wants=network.target

[Service]
Type=exec
User=ferritedb
Group=ferritedb
WorkingDirectory=/var/lib/ferritedb
ExecStart=/usr/local/bin/ferritedb serve --config /var/lib/ferritedb/config/ferritedb.toml
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=ferritedb

# Security settings
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/ferritedb

[Install]
WantedBy=multi-user.target
EOF

# Enable and start service
sudo systemctl enable ferritedb
sudo systemctl start ferritedb
```

#### 3. Kubernetes Deployment

```yaml
# ferritedb-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ferritedb
  labels:
    app: ferritedb
spec:
  replicas: 3
  selector:
    matchLabels:
      app: ferritedb
  template:
    metadata:
      labels:
        app: ferritedb
    spec:
      containers:
      - name: ferritedb
        image: ferritedb/ferritedb:latest
        ports:
        - containerPort: 8090
        env:
        - name: FERRITEDB_AUTH_JWT_SECRET
          valueFrom:
            secretKeyRef:
              name: ferritedb-secrets
              key: jwt-secret
        volumeMounts:
        - name: config
          mountPath: /app/ferritedb.toml
          subPath: ferritedb.toml
        - name: data
          mountPath: /app/data
        livenessProbe:
          httpGet:
            path: /healthz
            port: 8090
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /readyz
            port: 8090
          initialDelaySeconds: 5
          periodSeconds: 5
      volumes:
      - name: config
        configMap:
          name: ferritedb-config
      - name: data
        persistentVolumeClaim:
          claimName: ferritedb-data
---
apiVersion: v1
kind: Service
metadata:
  name: ferritedb-service
spec:
  selector:
    app: ferritedb
  ports:
  - protocol: TCP
    port: 80
    targetPort: 8090
  type: LoadBalancer
```

### Load Balancing

#### Nginx Configuration

```nginx
upstream ferritedb_backend {
    server 127.0.0.1:8090;
    # Add more servers for horizontal scaling
    # server 127.0.0.1:8091;
    # server 127.0.0.1:8092;
}

server {
    listen 80;
    listen 443 ssl http2;
    server_name api.yourdomain.com;

    # SSL configuration
    ssl_certificate /etc/ssl/certs/yourdomain.crt;
    ssl_certificate_key /etc/ssl/private/yourdomain.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512;

    # Security headers
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains";

    # Rate limiting
    limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;
    limit_req zone=api burst=20 nodelay;

    location / {
        proxy_pass http://ferritedb_backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # WebSocket support
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        
        # Timeouts
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }

    # Health check endpoint
    location /healthz {
        access_log off;
        proxy_pass http://ferritedb_backend;
    }
}
```

## Configuration Management

### Environment-Based Configuration

```bash
# Production environment variables
export FERRITEDB_SERVER_HOST="0.0.0.0"
export FERRITEDB_SERVER_PORT="8090"
export FERRITEDB_DATABASE_URL="sqlite:/var/lib/ferritedb/data/ferritedb.db"
export FERRITEDB_AUTH_JWT_SECRET="$(openssl rand -base64 64)"
export FERRITEDB_STORAGE_BACKEND="s3"
export FERRITEDB_STORAGE_S3_BUCKET="ferritedb-prod-files"
export FERRITEDB_STORAGE_S3_REGION="us-east-1"
export RUST_LOG="info"
```

### Configuration File Template

```toml
# /var/lib/ferritedb/config/ferritedb.toml
[server]
host = "0.0.0.0"
port = 8090
cors_origins = ["https://yourdomain.com"]

[server.rate_limit]
requests_per_minute = 60
burst_size = 10

[database]
url = "sqlite:/var/lib/ferritedb/data/ferritedb.db"
auto_migrate = true
max_connections = 20

[auth]
jwt_secret = "${FERRITEDB_AUTH_JWT_SECRET}"
token_ttl = 900      # 15 minutes
refresh_ttl = 86400  # 1 day
password_min_length = 12

[storage]
backend = "s3"

[storage.s3]
bucket = "${FERRITEDB_S3_BUCKET}"
region = "${FERRITEDB_S3_REGION}"
endpoint = "${FERRITEDB_S3_ENDPOINT}"  # Optional for S3-compatible services

[features]
oauth2 = true
s3_storage = true
image_transforms = false
multi_tenant = false
full_text_search = true
metrics = true

[logging]
level = "info"
format = "json"
```

### Secrets Management

#### Using HashiCorp Vault

```bash
# Store secrets in Vault
vault kv put secret/ferritedb \
  jwt_secret="$(openssl rand -base64 64)" \
  s3_access_key="AKIA..." \
  s3_secret_key="..."

# Retrieve in startup script
export FERRITEDB_AUTH_JWT_SECRET=$(vault kv get -field=jwt_secret secret/ferritedb)
```

#### Using Kubernetes Secrets

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: ferritedb-secrets
type: Opaque
data:
  jwt-secret: <base64-encoded-secret>
  s3-access-key: <base64-encoded-key>
  s3-secret-key: <base64-encoded-secret>
```

## Monitoring and Observability

### Health Checks

FerriteDB provides built-in health check endpoints:

- `/api/health`: Liveness probe (service is running)
- `/api/readyz`: Readiness probe (service can handle requests)

```bash
# Check service health
curl -f http://localhost:8090/api/health
curl -f http://localhost:8090/api/readyz
```

### Metrics Collection

#### Prometheus Integration

```yaml
# prometheus.yml
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'ferritedb'
    static_configs:
      - targets: ['localhost:8090']
    metrics_path: '/metrics'
    scrape_interval: 30s
```

#### Key Metrics to Monitor

- **Request Rate**: `http_requests_total`
- **Response Time**: `http_request_duration_seconds`
- **Error Rate**: `http_requests_total{status=~"5.."}` 
- **Database Connections**: `db_connections_active`
- **WebSocket Connections**: `websocket_connections_active`
- **File Storage Usage**: `storage_bytes_used`

### Logging

#### Structured Logging Configuration

```toml
[logging]
level = "info"
format = "json"
fields = ["timestamp", "level", "target", "message", "request_id"]
```

#### Log Aggregation with ELK Stack

```yaml
# filebeat.yml
filebeat.inputs:
- type: log
  enabled: true
  paths:
    - /var/log/ferritedb/*.log
  json.keys_under_root: true
  json.add_error_key: true

output.elasticsearch:
  hosts: ["elasticsearch:9200"]
  index: "ferritedb-logs-%{+yyyy.MM.dd}"
```

#### Log Analysis Queries

```bash
# Find authentication failures
grep "authentication_failed" /var/log/ferritedb/ferritedb.log

# Monitor error rates
grep "ERROR" /var/log/ferritedb/ferritedb.log | wc -l

# Track slow queries
grep "slow_query" /var/log/ferritedb/ferritedb.log
```

### Alerting

#### Prometheus Alerting Rules

```
# alerts.yml
groups:
- name: ferritedb
  rules:
  - alert: FerriteDBDown
    expr: up{job="ferritedb"} == 0
    for: 1m
    labels:
      severity: critical
    annotations:
      summary: "FerriteDB service is down"

  - alert: HighErrorRate
    expr: rate(http_requests_total{status=~"5.."}[5m]) > 0.1
    for: 2m
    labels:
      severity: warning
    annotations:
      summary: "High error rate detected"

  - alert: DatabaseConnectionsHigh
    expr: db_connections_active > 15
    for: 5m
    labels:
      severity: warning
    annotations:
      summary: "Database connection pool nearly exhausted"
```

## Backup and Recovery

### Database Backup

#### SQLite Backup

```bash
#!/bin/bash
# backup-database.sh

BACKUP_DIR="/var/backups/ferritedb"
DB_PATH="/var/lib/ferritedb/data/ferritedb.db"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="$BACKUP_DIR/ferritedb_$TIMESTAMP.db"

# Create backup directory
mkdir -p "$BACKUP_DIR"

# Create backup using SQLite backup API
sqlite3 "$DB_PATH" ".backup $BACKUP_FILE"

# Compress backup
gzip "$BACKUP_FILE"

# Keep only last 30 days of backups
find "$BACKUP_DIR" -name "ferritedb_*.db.gz" -mtime +30 -delete

echo "Backup completed: $BACKUP_FILE.gz"
```

#### Automated Backup with Cron

```bash
# Add to crontab
0 2 * * * /usr/local/bin/backup-database.sh >> /var/log/ferritedb/backup.log 2>&1
```

### File Storage Backup

#### Local Storage Backup

```bash
#!/bin/bash
# backup-files.sh

STORAGE_DIR="/var/lib/ferritedb/data/storage"
BACKUP_DIR="/var/backups/ferritedb/files"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Create incremental backup using rsync
rsync -av --link-dest="$BACKUP_DIR/latest" \
  "$STORAGE_DIR/" \
  "$BACKUP_DIR/$TIMESTAMP/"

# Update latest symlink
ln -sfn "$TIMESTAMP" "$BACKUP_DIR/latest"

echo "File backup completed: $BACKUP_DIR/$TIMESTAMP"
```

#### S3 Storage Backup

```bash
# S3 buckets have built-in versioning and cross-region replication
aws s3api put-bucket-versioning \
  --bucket ferritedb-prod-files \
  --versioning-configuration Status=Enabled

# Set up cross-region replication
aws s3api put-bucket-replication \
  --bucket ferritedb-prod-files \
  --replication-configuration file://replication.json
```

### Disaster Recovery

#### Recovery Procedures

1. **Database Recovery**
   ```bash
   # Stop service
   sudo systemctl stop ferritedb
   
   # Restore database
   gunzip -c /var/backups/ferritedb/ferritedb_20240115_020000.db.gz > /var/lib/ferritedb/data/ferritedb.db
   
   # Fix permissions
   chown ferritedb:ferritedb /var/lib/ferritedb/data/ferritedb.db
   
   # Start service
   sudo systemctl start ferritedb
   ```

2. **File Storage Recovery**
   ```bash
   # Restore files
   rsync -av /var/backups/ferritedb/files/latest/ /var/lib/ferritedb/data/storage/
   
   # Fix permissions
   chown -R ferritedb:ferritedb /var/lib/ferritedb/data/storage
   ```

3. **Complete System Recovery**
   ```bash
   # Deploy new instance
   docker-compose up -d
   
   # Restore data
   docker cp backup.db ferritedb:/app/data/ferritedb.db
   docker cp storage_backup/ ferritedb:/app/data/storage/
   
   # Restart with restored data
   docker-compose restart
   ```

## Security Operations

### Key Rotation

#### JWT Secret Rotation

```bash
#!/bin/bash
# rotate-jwt-secret.sh

# Generate new secret
NEW_SECRET=$(openssl rand -base64 64)

# Update configuration
sed -i "s/jwt_secret = .*/jwt_secret = \"$NEW_SECRET\"/" /var/lib/ferritedb/config/ferritedb.toml

# Restart service
sudo systemctl restart ferritedb

# Log rotation
echo "$(date): JWT secret rotated" >> /var/log/ferritedb/security.log
```

#### Database Encryption Key Rotation

```bash
# For SQLite with SQLCipher
sqlite3 encrypted.db "PRAGMA rekey = 'new-encryption-key';"
```

### Access Control Management

#### User Audit

```bash
# List all admin users
ferritedb admin list --role admin

# Check user activity
grep "user_id.*admin" /var/log/ferritedb/audit.log

# Disable inactive users
ferritedb admin disable --email inactive@example.com
```

#### Permission Review

```bash
# Export collection rules for review
ferritedb export collections --format json > collections_audit.json

# Review access rules
jq '.[] | {name: .name, rules: .rules}' collections_audit.json
```

### Security Monitoring

#### Failed Authentication Monitoring

```bash
# Monitor failed logins
tail -f /var/log/ferritedb/ferritedb.log | grep "authentication_failed"

# Count failed attempts by IP
grep "authentication_failed" /var/log/ferritedb/ferritedb.log | \
  jq -r '.ip_address' | sort | uniq -c | sort -nr
```

#### Intrusion Detection

```bash
# Monitor for suspicious patterns
grep -E "(sql_injection|xss_attempt|path_traversal)" /var/log/ferritedb/security.log

# Check for unusual admin activity
grep "admin_action" /var/log/ferritedb/audit.log | \
  jq 'select(.timestamp > "2024-01-15T00:00:00Z")'
```

## Performance Tuning

### Database Optimization

#### SQLite Configuration

```sql
-- Optimize SQLite for production
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA cache_size = 10000;
PRAGMA temp_store = MEMORY;
PRAGMA mmap_size = 268435456; -- 256MB
```

#### Connection Pool Tuning

```toml
[database]
max_connections = 20
min_connections = 5
acquire_timeout = 30
idle_timeout = 600
max_lifetime = 1800
```

### Application Performance

#### Memory Optimization

```bash
# Monitor memory usage
ps aux | grep ferritedb
cat /proc/$(pgrep ferritedb)/status | grep -E "(VmRSS|VmSize)"

# Set memory limits in systemd
echo "MemoryMax=512M" >> /etc/systemd/system/ferritedb.service
sudo systemctl daemon-reload
sudo systemctl restart ferritedb
```

#### CPU Optimization

```toml
# Adjust worker threads
[server]
worker_threads = 4  # Match CPU cores
max_blocking_threads = 512
```

### Caching Strategies

#### HTTP Caching

```nginx
# Nginx caching configuration
location ~* \.(js|css|png|jpg|jpeg|gif|ico|svg)$ {
    expires 1y;
    add_header Cache-Control "public, immutable";
}

location /api/ {
    # Cache GET requests for 5 minutes
    proxy_cache_valid 200 5m;
    proxy_cache_key "$scheme$request_method$host$request_uri";
}
```

#### Application-Level Caching

```rust
// Example: Cache collection schemas
use moka::future::Cache;

let schema_cache: Cache<String, CollectionSchema> = Cache::builder()
    .max_capacity(1000)
    .time_to_live(Duration::from_secs(300))
    .build();
```

## Troubleshooting

### Common Issues

#### Service Won't Start

```bash
# Check service status
sudo systemctl status ferritedb

# Check logs
sudo journalctl -u ferritedb -f

# Check configuration
ferritedb --config /var/lib/ferritedb/config/ferritedb.toml validate

# Check file permissions
ls -la /var/lib/ferritedb/
```

#### Database Connection Issues

```bash
# Check database file
sqlite3 /var/lib/ferritedb/data/ferritedb.db ".schema"

# Check file locks
lsof /var/lib/ferritedb/data/ferritedb.db

# Check disk space
df -h /var/lib/ferritedb/
```

#### High Memory Usage

```bash
# Check memory usage
top -p $(pgrep ferritedb)

# Check for memory leaks
valgrind --tool=memcheck --leak-check=full ferritedb serve

# Analyze heap usage
heaptrack ferritedb serve
```

#### Performance Issues

```bash
# Check system resources
htop
iotop
nethogs

# Profile application
perf record -g ferritedb serve
perf report

# Check database performance
sqlite3 /var/lib/ferritedb/data/ferritedb.db "EXPLAIN QUERY PLAN SELECT ..."
```

### Debug Mode

```bash
# Enable debug logging
export RUST_LOG=debug
ferritedb serve

# Enable SQL query logging
export RUST_LOG=sqlx=debug,ferritedb=debug
ferritedb serve
```

### Log Analysis

```bash
# Parse JSON logs
cat /var/log/ferritedb/ferritedb.log | jq 'select(.level == "ERROR")'

# Find slow requests
cat /var/log/ferritedb/ferritedb.log | jq 'select(.duration_ms > 1000)'

# Analyze request patterns
cat /var/log/ferritedb/ferritedb.log | jq -r '.path' | sort | uniq -c | sort -nr
```

## Maintenance

### Regular Maintenance Tasks

#### Daily Tasks

```bash
#!/bin/bash
# daily-maintenance.sh

# Check service health
curl -f http://localhost:8090/healthz || echo "Health check failed"

# Check disk space
df -h | awk '$5 > 80 {print "Disk usage high: " $0}'

# Rotate logs
logrotate /etc/logrotate.d/ferritedb

# Backup database
/usr/local/bin/backup-database.sh
```

#### Weekly Tasks

```bash
#!/bin/bash
# weekly-maintenance.sh

# Update system packages
sudo apt update && sudo apt upgrade -y

# Check for FerriteDB updates
ferritedb --version
curl -s https://api.github.com/repos/ferritedb/ferritedb/releases/latest | jq -r '.tag_name'

# Analyze logs for errors
grep "ERROR" /var/log/ferritedb/ferritedb.log | tail -100

# Database maintenance
sqlite3 /var/lib/ferritedb/data/ferritedb.db "VACUUM; ANALYZE;"
```

#### Monthly Tasks

```bash
#!/bin/bash
# monthly-maintenance.sh

# Security audit
cargo audit

# Performance review
analyze-performance-logs.sh

# Backup verification
test-backup-restore.sh

# Certificate renewal (if using Let's Encrypt)
certbot renew --dry-run
```

### Update Procedures

#### Application Updates

```bash
# Backup before update
/usr/local/bin/backup-database.sh

# Download new version
curl -L https://github.com/ferritedb/ferritedb/releases/latest/download/ferritedb-linux-x86_64.tar.gz | tar xz

# Stop service
sudo systemctl stop ferritedb

# Replace binary
sudo mv ferritedb /usr/local/bin/ferritedb
sudo chmod +x /usr/local/bin/ferritedb

# Run migrations
sudo -u ferritedb ferritedb migrate run --config /var/lib/ferritedb/config/ferritedb.toml

# Start service
sudo systemctl start ferritedb

# Verify update
curl -f http://localhost:8090/healthz
```

#### Docker Updates

```bash
# Pull new image
docker pull ferritedb/ferritedb:latest

# Update with zero downtime
docker-compose up -d --no-deps ferritedb

# Verify deployment
docker-compose ps
docker-compose logs ferritedb
```

### Capacity Planning

#### Growth Monitoring

```bash
# Database size growth
du -h /var/lib/ferritedb/data/ferritedb.db

# File storage growth
du -sh /var/lib/ferritedb/data/storage/

# Request volume trends
grep "http_request" /var/log/ferritedb/ferritedb.log | \
  awk '{print $1}' | cut -d'T' -f1 | sort | uniq -c
```

#### Scaling Indicators

Monitor these metrics for scaling decisions:

- CPU usage consistently > 70%
- Memory usage > 80%
- Database connections > 80% of pool
- Response time > 500ms for 95th percentile
- Disk usage > 80%

---

This operations guide provides a comprehensive framework for running FerriteDB in production. Adapt the procedures to your specific environment and requirements.