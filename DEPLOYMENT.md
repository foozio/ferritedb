# FerriteDB Deployment Guide

This guide covers various deployment options for FerriteDB, from simple single-server deployments to production-ready cloud configurations.

## 📋 Table of Contents

- [Prerequisites](#prerequisites)
- [Single Binary Deployment](#single-binary-deployment)
- [Docker Deployment](#docker-deployment)
- [Cloud Platforms](#cloud-platforms)
- [Production Hardening](#production-hardening)
- [Monitoring & Observability](#monitoring--observability)
- [Backup & Recovery](#backup--recovery)
- [Scaling Considerations](#scaling-considerations)

## Prerequisites

### System Requirements

**Minimum:**
- CPU: 1 vCPU
- RAM: 512MB
- Storage: 1GB
- OS: Linux, macOS, or Windows

**Recommended (Production):**
- CPU: 2+ vCPUs
- RAM: 2GB+
- Storage: 10GB+ SSD
- OS: Linux (Ubuntu 20.04+ or similar)

### Network Requirements

- **Port 8090**: HTTP/WebSocket traffic (configurable)
- **Outbound HTTPS**: For S3 storage (if used)
- **Outbound DNS**: For domain resolution

## Single Binary Deployment

### 1. Download and Setup

```bash
# Create application directory
sudo mkdir -p /opt/ferritedb
cd /opt/ferritedb

# Download latest release
curl -L https://github.com/ferritedb/ferritedb/releases/latest/download/ferritedb-linux-x64 -o ferritedb
chmod +x ferritedb

# Create data directory
mkdir -p data/storage

# Create configuration
cat > ferritedb.toml << EOF
[server]
host = "0.0.0.0"
port = 8090

[database]
url = "sqlite:data/ferritedb.db"
auto_migrate = true

[auth]
jwt_secret = "$(openssl rand -base64 32)"

[storage]
backend = "local"

[storage.local]
base_path = "data/storage"
EOF
```

### 2. Create System Service

```bash
# Create systemd service
sudo tee /etc/systemd/system/ferritedb.service << EOF
[Unit]
Description=FerriteDB Backend Service
After=network.target
Wants=network.target

[Service]
Type=simple
User=ferritedb
Group=ferritedb
WorkingDirectory=/opt/ferritedb
ExecStart=/opt/ferritedb/ferritedb serve
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
ReadWritePaths=/opt/ferritedb/data

# Resource limits
LimitNOFILE=65536
LimitNPROC=4096

[Install]
WantedBy=multi-user.target
EOF

# Create user
sudo useradd --system --home /opt/ferritedb --shell /bin/false ferritedb
sudo chown -R ferritedb:ferritedb /opt/ferritedb

# Enable and start service
sudo systemctl daemon-reload
sudo systemctl enable ferritedb
sudo systemctl start ferritedb

# Check status
sudo systemctl status ferritedb
```

### 3. Setup Reverse Proxy (Nginx)

```bash
# Install Nginx
sudo apt update
sudo apt install nginx

# Create site configuration
sudo tee /etc/nginx/sites-available/ferritedb << EOF
server {
    listen 80;
    server_name your-domain.com;

    # Security headers
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";
    add_header Referrer-Policy strict-origin-when-cross-origin;

    # Rate limiting
    limit_req_zone \$binary_remote_addr zone=api:10m rate=10r/s;
    limit_req zone=api burst=20 nodelay;

    # Proxy to FerriteDB
    location / {
        proxy_pass http://127.0.0.1:8090;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_cache_bypass \$http_upgrade;
        
        # Timeouts
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }

    # WebSocket support
    location /realtime {
        proxy_pass http://127.0.0.1:8090;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }

    # File uploads
    client_max_body_size 50M;
}
EOF

# Enable site
sudo ln -s /etc/nginx/sites-available/ferritedb /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
```

### 4. SSL Certificate (Let's Encrypt)

```bash
# Install Certbot
sudo apt install certbot python3-certbot-nginx

# Get certificate
sudo certbot --nginx -d your-domain.com

# Auto-renewal (already configured by certbot)
sudo systemctl status certbot.timer
```

## Docker Deployment

### 1. Dockerfile

```dockerfile
# Multi-stage build
FROM rust:1.75 as builder

WORKDIR /app
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim

# Install dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create app user
RUN useradd --create-home --shell /bin/bash app

# Copy binary
COPY --from=builder /app/target/release/ferritedb /usr/local/bin/ferritedb

# Create directories
RUN mkdir -p /app/data/storage && chown -R app:app /app

USER app
WORKDIR /app

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8090/healthz || exit 1

EXPOSE 8090

CMD ["ferritedb", "serve"]
```

### 2. Docker Compose

```yaml
version: '3.8'

services:
  ferritedb:
    build: .
    # Or use pre-built image:
    # image: ferritedb/ferritedb:latest
    container_name: ferritedb
    restart: unless-stopped
    ports:
      - "8090:8090"
    volumes:
      - ferritedb_data:/app/data
      - ./ferritedb.toml:/app/ferritedb.toml:ro
    environment:
      - FERRITEDB_AUTH_JWT_SECRET=${JWT_SECRET}
      - FERRITEDB_DATABASE_URL=sqlite:data/ferritedb.db
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8090/healthz"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s
    networks:
      - ferritedb_network

  # Reverse proxy
  nginx:
    image: nginx:alpine
    container_name: ferritedb_nginx
    restart: unless-stopped
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf:ro
      - ./ssl:/etc/nginx/ssl:ro
      - nginx_cache:/var/cache/nginx
    depends_on:
      - ferritedb
    networks:
      - ferritedb_network

  # Optional: Monitoring
  prometheus:
    image: prom/prometheus:latest
    container_name: ferritedb_prometheus
    restart: unless-stopped
    ports:
      - "9090:9090"
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml:ro
      - prometheus_data:/prometheus
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'
      - '--web.console.libraries=/etc/prometheus/console_libraries'
      - '--web.console.templates=/etc/prometheus/consoles'
    networks:
      - ferritedb_network

volumes:
  ferritedb_data:
  nginx_cache:
  prometheus_data:

networks:
  ferritedb_network:
    driver: bridge
```

### 3. Environment Configuration

```bash
# Create .env file
cat > .env << EOF
JWT_SECRET=$(openssl rand -base64 32)
FERRITEDB_SERVER_HOST=0.0.0.0
FERRITEDB_SERVER_PORT=8090
FERRITEDB_DATABASE_URL=sqlite:data/ferritedb.db
FERRITEDB_STORAGE_BACKEND=local
FERRITEDB_STORAGE_LOCAL_BASE_PATH=data/storage
EOF

# Start services
docker-compose up -d

# View logs
docker-compose logs -f ferritedb

# Scale if needed
docker-compose up -d --scale ferritedb=3
```

## Cloud Platforms

### AWS ECS with Fargate

```yaml
# task-definition.json
{
  "family": "ferritedb",
  "networkMode": "awsvpc",
  "requiresCompatibilities": ["FARGATE"],
  "cpu": "512",
  "memory": "1024",
  "executionRoleArn": "arn:aws:iam::ACCOUNT:role/ecsTaskExecutionRole",
  "taskRoleArn": "arn:aws:iam::ACCOUNT:role/ferritedbTaskRole",
  "containerDefinitions": [
    {
      "name": "ferritedb",
      "image": "ferritedb/ferritedb:latest",
      "portMappings": [
        {
          "containerPort": 8090,
          "protocol": "tcp"
        }
      ],
      "environment": [
        {
          "name": "FERRITEDB_AUTH_JWT_SECRET",
          "value": "your-secret-from-secrets-manager"
        },
        {
          "name": "FERRITEDB_STORAGE_BACKEND",
          "value": "s3"
        },
        {
          "name": "FERRITEDB_STORAGE_S3_BUCKET",
          "value": "your-ferritedb-files"
        }
      ],
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "/ecs/ferritedb",
          "awslogs-region": "us-east-1",
          "awslogs-stream-prefix": "ecs"
        }
      },
      "healthCheck": {
        "command": ["CMD-SHELL", "curl -f http://localhost:8090/healthz || exit 1"],
        "interval": 30,
        "timeout": 5,
        "retries": 3,
        "startPeriod": 60
      }
    }
  ]
}
```

### Google Cloud Run

```yaml
# cloudrun.yaml
apiVersion: serving.knative.dev/v1
kind: Service
metadata:
  name: ferritedb
  annotations:
    run.googleapis.com/ingress: all
spec:
  template:
    metadata:
      annotations:
        autoscaling.knative.dev/maxScale: "10"
        run.googleapis.com/cpu-throttling: "false"
        run.googleapis.com/execution-environment: gen2
    spec:
      containerConcurrency: 100
      timeoutSeconds: 300
      containers:
      - image: gcr.io/PROJECT_ID/ferritedb:latest
        ports:
        - containerPort: 8090
        env:
        - name: FERRITEDB_AUTH_JWT_SECRET
          valueFrom:
            secretKeyRef:
              name: ferritedb-secrets
              key: jwt-secret
        - name: FERRITEDB_DATABASE_URL
          value: "sqlite:data/ferritedb.db"
        resources:
          limits:
            cpu: "1"
            memory: "1Gi"
        volumeMounts:
        - name: data
          mountPath: /app/data
      volumes:
      - name: data
        persistentVolumeClaim:
          claimName: ferritedb-data
```

### Railway

```bash
# Install Railway CLI
npm install -g @railway/cli

# Login and initialize
railway login
railway init

# Set environment variables
railway variables set FERRITEDB_AUTH_JWT_SECRET=$(openssl rand -base64 32)
railway variables set FERRITEDB_DATABASE_URL=sqlite:data/ferritedb.db

# Deploy
railway up
```

### Fly.io

```toml
# fly.toml
app = "ferritedb-app"
primary_region = "ord"

[build]
  image = "ferritedb/ferritedb:latest"

[env]
  FERRITEDB_SERVER_HOST = "0.0.0.0"
  FERRITEDB_SERVER_PORT = "8080"

[[services]]
  http_checks = []
  internal_port = 8080
  processes = ["app"]
  protocol = "tcp"
  script_checks = []

  [services.concurrency]
    hard_limit = 25
    soft_limit = 20
    type = "connections"

  [[services.ports]]
    force_https = true
    handlers = ["http"]
    port = 80

  [[services.ports]]
    handlers = ["tls", "http"]
    port = 443

  [[services.tcp_checks]]
    grace_period = "1s"
    interval = "15s"
    restart_limit = 0
    timeout = "2s"

[[mounts]]
  source = "ferritedb_data"
  destination = "/app/data"
```

## Production Hardening

### 1. Security Configuration

```toml
# ferritedb.toml - Production settings
[server]
host = "127.0.0.1"  # Bind to localhost only
port = 8090
request_timeout = 30
max_request_size = 10485760  # 10MB

[server.rate_limit]
requests_per_minute = 120
burst_size = 20

[auth]
jwt_secret = "use-a-strong-secret-from-env"
token_ttl = 900      # 15 minutes
refresh_ttl = 86400  # 24 hours
password_min_length = 12

[database]
url = "sqlite:data/ferritedb.db?mode=rwc&cache=shared&_journal_mode=WAL"
max_connections = 20
connection_timeout = 30

[storage]
backend = "s3"  # Use S3 for production

[storage.s3]
bucket = "your-production-bucket"
region = "us-east-1"
```

### 2. Firewall Configuration

```bash
# UFW (Ubuntu)
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow ssh
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw enable

# iptables (alternative)
iptables -A INPUT -p tcp --dport 22 -j ACCEPT
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -j ACCEPT
iptables -A INPUT -j DROP
```

### 3. SSL/TLS Configuration

```nginx
# nginx-ssl.conf
server {
    listen 443 ssl http2;
    server_name your-domain.com;

    # SSL Configuration
    ssl_certificate /etc/letsencrypt/live/your-domain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/your-domain.com/privkey.pem;
    
    # Modern SSL configuration
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;
    
    # HSTS
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    
    # Security headers
    add_header X-Frame-Options DENY always;
    add_header X-Content-Type-Options nosniff always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';" always;

    # Rest of configuration...
}

# Redirect HTTP to HTTPS
server {
    listen 80;
    server_name your-domain.com;
    return 301 https://$server_name$request_uri;
}
```

### 4. Log Management

```bash
# Logrotate configuration
sudo tee /etc/logrotate.d/ferritedb << EOF
/var/log/ferritedb/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    create 644 ferritedb ferritedb
    postrotate
        systemctl reload ferritedb
    endscript
}
EOF

# Rsyslog configuration for structured logging
sudo tee /etc/rsyslog.d/30-ferritedb.conf << EOF
if \$programname == 'ferritedb' then /var/log/ferritedb/ferritedb.log
& stop
EOF

sudo systemctl restart rsyslog
```

## Monitoring & Observability

### 1. Health Checks

```bash
# Basic health check script
#!/bin/bash
# health-check.sh

ENDPOINT="http://localhost:8090/healthz"
TIMEOUT=5

if curl -f -s --max-time $TIMEOUT $ENDPOINT > /dev/null; then
    echo "✅ FerriteDB is healthy"
    exit 0
else
    echo "❌ FerriteDB health check failed"
    exit 1
fi
```

### 2. Prometheus Metrics

```yaml
# prometheus.yml
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'ferritedb'
    static_configs:
      - targets: ['ferritedb:8090']
    metrics_path: '/metrics'
    scrape_interval: 30s
```

### 3. Grafana Dashboard

```json
{
  "dashboard": {
    "title": "FerriteDB Monitoring",
    "panels": [
      {
        "title": "Request Rate",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(http_requests_total[5m])",
            "legendFormat": "{{method}} {{status}}"
          }
        ]
      },
      {
        "title": "Response Time",
        "type": "graph",
        "targets": [
          {
            "expr": "histogram_quantile(0.95, rate(http_request_duration_seconds_bucket[5m]))",
            "legendFormat": "95th percentile"
          }
        ]
      },
      {
        "title": "Database Connections",
        "type": "singlestat",
        "targets": [
          {
            "expr": "ferritedb_db_connections_active"
          }
        ]
      }
    ]
  }
}
```

### 4. Log Aggregation (ELK Stack)

```yaml
# docker-compose-elk.yml
version: '3.8'

services:
  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:8.8.0
    environment:
      - discovery.type=single-node
      - xpack.security.enabled=false
    volumes:
      - elasticsearch_data:/usr/share/elasticsearch/data

  logstash:
    image: docker.elastic.co/logstash/logstash:8.8.0
    volumes:
      - ./logstash.conf:/usr/share/logstash/pipeline/logstash.conf
    depends_on:
      - elasticsearch

  kibana:
    image: docker.elastic.co/kibana/kibana:8.8.0
    ports:
      - "5601:5601"
    environment:
      - ELASTICSEARCH_HOSTS=http://elasticsearch:9200
    depends_on:
      - elasticsearch

volumes:
  elasticsearch_data:
```

## Backup & Recovery

### 1. Database Backup

```bash
#!/bin/bash
# backup-db.sh

BACKUP_DIR="/opt/ferritedb/backups"
DB_PATH="/opt/ferritedb/data/ferritedb.db"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="$BACKUP_DIR/ferritedb_backup_$TIMESTAMP.db"

# Create backup directory
mkdir -p $BACKUP_DIR

# Create backup using SQLite backup API
sqlite3 $DB_PATH ".backup $BACKUP_FILE"

# Compress backup
gzip $BACKUP_FILE

# Clean old backups (keep 30 days)
find $BACKUP_DIR -name "ferritedb_backup_*.db.gz" -mtime +30 -delete

echo "Backup completed: $BACKUP_FILE.gz"
```

### 2. File Storage Backup

```bash
#!/bin/bash
# backup-files.sh

STORAGE_DIR="/opt/ferritedb/data/storage"
BACKUP_DIR="/opt/ferritedb/backups"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Create incremental backup using rsync
rsync -av --link-dest="$BACKUP_DIR/latest" \
      "$STORAGE_DIR/" \
      "$BACKUP_DIR/files_$TIMESTAMP/"

# Update latest symlink
rm -f "$BACKUP_DIR/latest"
ln -s "files_$TIMESTAMP" "$BACKUP_DIR/latest"

echo "File backup completed: $BACKUP_DIR/files_$TIMESTAMP"
```

### 3. Automated Backup with Cron

```bash
# Add to crontab
crontab -e

# Database backup every 6 hours
0 */6 * * * /opt/ferritedb/scripts/backup-db.sh

# File backup daily at 2 AM
0 2 * * * /opt/ferritedb/scripts/backup-files.sh

# Upload to S3 daily at 3 AM
0 3 * * * aws s3 sync /opt/ferritedb/backups/ s3://your-backup-bucket/ferritedb/
```

### 4. Disaster Recovery

```bash
#!/bin/bash
# restore.sh

BACKUP_FILE="$1"
STORAGE_BACKUP="$2"

if [ -z "$BACKUP_FILE" ]; then
    echo "Usage: $0 <backup_file> [storage_backup_dir]"
    exit 1
fi

# Stop FerriteDB
sudo systemctl stop ferritedb

# Restore database
if [ -f "$BACKUP_FILE" ]; then
    echo "Restoring database from $BACKUP_FILE"
    cp "$BACKUP_FILE" /opt/ferritedb/data/ferritedb.db
    chown ferritedb:ferritedb /opt/ferritedb/data/ferritedb.db
fi

# Restore file storage
if [ -n "$STORAGE_BACKUP" ] && [ -d "$STORAGE_BACKUP" ]; then
    echo "Restoring file storage from $STORAGE_BACKUP"
    rm -rf /opt/ferritedb/data/storage
    cp -r "$STORAGE_BACKUP" /opt/ferritedb/data/storage
    chown -R ferritedb:ferritedb /opt/ferritedb/data/storage
fi

# Start FerriteDB
sudo systemctl start ferritedb

echo "Restore completed"
```

## Scaling Considerations

### 1. Horizontal Scaling

FerriteDB can be scaled horizontally with some considerations:

```yaml
# docker-compose-scaled.yml
version: '3.8'

services:
  ferritedb:
    image: ferritedb/ferritedb:latest
    deploy:
      replicas: 3
    volumes:
      - shared_storage:/app/data/storage
    environment:
      - FERRITEDB_DATABASE_URL=postgresql://user:pass@postgres:5432/ferritedb
      - FERRITEDB_STORAGE_BACKEND=s3

  postgres:
    image: postgres:15
    environment:
      - POSTGRES_DB=ferritedb
      - POSTGRES_USER=ferritedb
      - POSTGRES_PASSWORD=secure_password
    volumes:
      - postgres_data:/var/lib/postgresql/data

  redis:
    image: redis:7-alpine
    command: redis-server --appendonly yes
    volumes:
      - redis_data:/data

  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
    volumes:
      - ./nginx-lb.conf:/etc/nginx/nginx.conf
    depends_on:
      - ferritedb

volumes:
  shared_storage:
  postgres_data:
  redis_data:
```

### 2. Load Balancer Configuration

```nginx
# nginx-lb.conf
upstream ferritedb_backend {
    least_conn;
    server ferritedb_1:8090 max_fails=3 fail_timeout=30s;
    server ferritedb_2:8090 max_fails=3 fail_timeout=30s;
    server ferritedb_3:8090 max_fails=3 fail_timeout=30s;
}

server {
    listen 80;
    
    location / {
        proxy_pass http://ferritedb_backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        
        # Health check
        proxy_next_upstream error timeout invalid_header http_500 http_502 http_503;
    }
    
    # Sticky sessions for WebSocket
    location /realtime {
        proxy_pass http://ferritedb_backend;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        
        # Enable session affinity
        ip_hash;
    }
}
```

### 3. Performance Tuning

```toml
# ferritedb-production.toml
[server]
host = "0.0.0.0"
port = 8090
request_timeout = 30
max_request_size = 52428800  # 50MB

[server.rate_limit]
requests_per_minute = 300
burst_size = 50

[database]
url = "sqlite:data/ferritedb.db?cache=shared&_journal_mode=WAL&_synchronous=NORMAL&_cache_size=10000"
max_connections = 50
connection_timeout = 10

[auth]
token_ttl = 900      # 15 minutes
refresh_ttl = 86400  # 24 hours

[storage]
backend = "s3"

[features]
metrics = true
```

---

This deployment guide covers the most common scenarios for deploying FerriteDB. For specific questions or advanced configurations, please refer to the [documentation](https://ferritedb.dev/docs) or join our [community](https://discord.gg/ferritedb).  
            key: jwt-secret
        resources:
          limits:
            cpu: 1000m
            memory: 1Gi
          requests:
            cpu: 100m
            memory: 128Mi
```

#### Azure Container Instances
```bash
# Deploy to Azure Container Instances
az container create \
  --resource-group myResourceGroup \
  --name ferritedb \
  --image ferritedb/ferritedb:latest \
  --dns-name-label ferritedb-unique \
  --ports 8090 \
  --environment-variables \
    FERRITEDB_AUTH_JWT_SECRET=your-jwt-secret \
  --secure-environment-variables \
    FERRITEDB_DATABASE_URL=postgresql://user:pass@host:5432/db
```

## Production Considerations

### High Availability Setup

#### Load Balancer Configuration (Nginx)
```nginx
# /etc/nginx/sites-available/ferritedb
upstream ferritedb_backend {
    least_conn;
    server ferritedb1:8090 max_fails=3 fail_timeout=30s;
    server ferritedb2:8090 max_fails=3 fail_timeout=30s;
    server ferritedb3:8090 max_fails=3 fail_timeout=30s;
}

server {
    listen 80;
    listen 443 ssl http2;
    server_name api.yourdomain.com;

    # SSL Configuration
    ssl_certificate /etc/ssl/certs/ferritedb.crt;
    ssl_certificate_key /etc/ssl/private/ferritedb.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512;
    ssl_prefer_server_ciphers off;

    # Security Headers
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload";

    # Rate Limiting
    limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;
    limit_req zone=api burst=20 nodelay;

    # Proxy Configuration
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
    location /health {
        access_log off;
        proxy_pass http://ferritedb_backend/api/health;
    }
}
```

### Database Configuration

#### PostgreSQL Production Setup
```sql
-- Create database and user
CREATE DATABASE ferritedb;
CREATE USER ferritedb_user WITH ENCRYPTED PASSWORD 'secure_password';
GRANT ALL PRIVILEGES ON DATABASE ferritedb TO ferritedb_user;

-- Performance tuning
ALTER SYSTEM SET shared_buffers = '256MB';
ALTER SYSTEM SET effective_cache_size = '1GB';
ALTER SYSTEM SET maintenance_work_mem = '64MB';
ALTER SYSTEM SET checkpoint_completion_target = 0.9;
ALTER SYSTEM SET wal_buffers = '16MB';
ALTER SYSTEM SET default_statistics_target = 100;
```

#### Connection Pooling with PgBouncer
```ini
# /etc/pgbouncer/pgbouncer.ini
[databases]
ferritedb = host=localhost port=5432 dbname=ferritedb

[pgbouncer]
listen_port = 6432
listen_addr = 127.0.0.1
auth_type = md5
auth_file = /etc/pgbouncer/userlist.txt
logfile = /var/log/pgbouncer/pgbouncer.log
pidfile = /var/run/pgbouncer/pgbouncer.pid
admin_users = postgres
stats_users = stats, postgres
pool_mode = transaction
server_reset_query = DISCARD ALL
max_client_conn = 100
default_pool_size = 20
```

### Backup and Recovery

#### Automated Backup Script
```bash
#!/bin/bash
# backup-ferritedb.sh

set -e

BACKUP_DIR="/backups/ferritedb"
DATE=$(date +%Y%m%d_%H%M%S)
RETENTION_DAYS=30

# Create backup directory
mkdir -p "$BACKUP_DIR"

# Database backup
if [[ "$DATABASE_TYPE" == "postgresql" ]]; then
    pg_dump "$DATABASE_URL" | gzip > "$BACKUP_DIR/db_$DATE.sql.gz"
elif [[ "$DATABASE_TYPE" == "sqlite" ]]; then
    sqlite3 "$SQLITE_PATH" ".backup '$BACKUP_DIR/db_$DATE.sqlite'"
    gzip "$BACKUP_DIR/db_$DATE.sqlite"
fi

# Files backup
tar -czf "$BACKUP_DIR/files_$DATE.tar.gz" -C "$FILES_PATH" .

# Upload to S3 (optional)
if [[ -n "$S3_BACKUP_BUCKET" ]]; then
    aws s3 cp "$BACKUP_DIR/db_$DATE.sql.gz" "s3://$S3_BACKUP_BUCKET/database/"
    aws s3 cp "$BACKUP_DIR/files_$DATE.tar.gz" "s3://$S3_BACKUP_BUCKET/files/"
fi

# Cleanup old backups
find "$BACKUP_DIR" -name "*.gz" -mtime +$RETENTION_DAYS -delete

echo "Backup completed: $DATE"
```

## Monitoring and Maintenance

### Health Checks
```bash
# Basic health check
curl -f http://localhost:8090/api/health

# Detailed readiness check
curl -f http://localhost:8090/api/readyz

# Custom health check script
#!/bin/bash
response=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8090/api/health)
if [ $response -eq 200 ]; then
    echo "FerriteDB is healthy"
    exit 0
else
    echo "FerriteDB is unhealthy (HTTP $response)"
    exit 1
fi
```

## Security Best Practices

### SSL/TLS Configuration
```bash
# Generate SSL certificate with Let's Encrypt
certbot --nginx -d api.yourdomain.com

# Or use self-signed for development
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
```

### Firewall Configuration
```bash
# UFW (Ubuntu)
sudo ufw allow 22/tcp    # SSH
sudo ufw allow 80/tcp    # HTTP
sudo ufw allow 443/tcp   # HTTPS
sudo ufw deny 8090/tcp   # Block direct access to FerriteDB
sudo ufw enable

# iptables
iptables -A INPUT -p tcp --dport 22 -j ACCEPT
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -j ACCEPT
iptables -A INPUT -p tcp --dport 8090 -s 127.0.0.1 -j ACCEPT
iptables -A INPUT -p tcp --dport 8090 -j DROP
```

---

*This deployment guide is maintained by the FerriteDB team and updated with each release.*