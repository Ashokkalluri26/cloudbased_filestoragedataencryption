# SecureCloud Deployment Guide

## Overview
SecureCloud is a comprehensive, secure cloud-based file storage platform with end-to-end AES-256 encryption, passwordless WebAuthn authentication, real-time features, offline support, and accessibility compliance.

## Features Completed ✅
- **Backend**: Flask with Oracle DB, WebSocket support, chunked uploads
- **Security**: Zero-knowledge AES-256-GCM encryption, WebAuthn passkeys, 2FA
- **Frontend**: Modern TailwindCSS UI with dark mode and high-contrast accessibility
- **Real-time**: WebSocket-based dashboard updates and activity feeds
- **Offline**: Service worker with background sync and PWA support
- **Collaboration**: Secure file sharing with expiring links and permissions
- **AI**: File categorization and tagging system
- **Accessibility**: WCAG compliance with keyboard navigation and screen reader support

## Prerequisites

### System Requirements
- Python 3.8+
- Oracle Database 19c+ (or Oracle XE for development)
- Redis Server 6.0+
- Node.js 16+ (for frontend build tools, optional)

### Python Dependencies
```bash
pip install -r requirements.txt
```

### Environment Variables
Create a `.env` file with the following variables:

```env
# Flask Configuration
SECRET_KEY=your-super-secret-key-here
FLASK_ENV=production
FLASK_DEBUG=False

# Database Configuration
ORACLE_USER=your_oracle_username
ORACLE_PASSWORD=your_oracle_password
ORACLE_DSN=localhost:1521/XE

# File Storage
UPLOAD_FOLDER=uploads
MAX_CONTENT_LENGTH=104857600  # 100MB

# Redis Configuration
REDIS_URL=redis://localhost:6379/0

# WebAuthn Configuration
WEBAUTHN_RP_ID=yourdomain.com
WEBAUTHN_RP_NAME=SecureCloud
WEBAUTHN_ORIGIN=https://yourdomain.com

# Security
BCRYPT_LOG_ROUNDS=12
SESSION_COOKIE_SECURE=True
SESSION_COOKIE_HTTPONLY=True
```

## Database Setup

### 1. Create Oracle Database Schema
```sql
-- Run the oracle_schema.sql file
sqlplus username/password@database @oracle_schema.sql
```

### 2. Initialize Database
```bash
python migrate_db.py
```

## Deployment Options

### Option 1: Production Server (Recommended)

#### 1. Install Dependencies
```bash
# System packages
sudo apt update
sudo apt install python3-pip python3-venv nginx redis-server

# Oracle Instant Client (for Oracle DB connectivity)
wget https://download.oracle.com/otn_software/linux/instantclient/instantclient-basic-linux.x64-21.8.0.0.0dbru.zip
sudo unzip instantclient-basic-linux.x64-21.8.0.0.0dbru.zip -d /opt/oracle/
echo 'export LD_LIBRARY_PATH=/opt/oracle/instantclient_21_8:$LD_LIBRARY_PATH' >> ~/.bashrc
source ~/.bashrc
```

#### 2. Setup Application
```bash
# Create application directory
sudo mkdir -p /var/www/securecloud
sudo chown $USER:$USER /var/www/securecloud
cd /var/www/securecloud

# Clone/copy your application files
cp -r /path/to/your/project/* .

# Create virtual environment
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Set permissions
sudo chown -R www-data:www-data uploads/
sudo chmod -R 755 uploads/
```

#### 3. Configure Gunicorn
Create `/var/www/securecloud/gunicorn.conf.py`:
```python
bind = "127.0.0.1:8000"
workers = 4
worker_class = "eventlet"
worker_connections = 1000
timeout = 30
keepalive = 2
max_requests = 1000
max_requests_jitter = 100
preload_app = True
```

#### 4. Create Systemd Service
Create `/etc/systemd/system/securecloud.service`:
```ini
[Unit]
Description=SecureCloud Flask Application
After=network.target

[Service]
User=www-data
Group=www-data
WorkingDirectory=/var/www/securecloud
Environment="PATH=/var/www/securecloud/venv/bin"
ExecStart=/var/www/securecloud/venv/bin/gunicorn --config gunicorn.conf.py app_enhanced:app
Restart=always

[Install]
WantedBy=multi-user.target
```

#### 5. Configure Nginx
Create `/etc/nginx/sites-available/securecloud`:
```nginx
server {
    listen 80;
    server_name yourdomain.com;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name yourdomain.com;

    ssl_certificate /path/to/ssl/cert.pem;
    ssl_certificate_key /path/to/ssl/private.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;

    client_max_body_size 100M;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location /socket.io/ {
        proxy_pass http://127.0.0.1:8000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location /static/ {
        alias /var/www/securecloud/static/;
        expires 1y;
        add_header Cache-Control "public, immutable";
    }
}
```

#### 6. Start Services
```bash
# Enable and start services
sudo systemctl enable securecloud
sudo systemctl start securecloud
sudo systemctl enable nginx
sudo systemctl start nginx
sudo systemctl enable redis-server
sudo systemctl start redis-server

# Check status
sudo systemctl status securecloud
sudo systemctl status nginx
sudo systemctl status redis-server
```

### Option 2: Docker Deployment

#### 1. Create Dockerfile
```dockerfile
FROM python:3.9-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    libaio1 \
    wget \
    unzip \
    && rm -rf /var/lib/apt/lists/*

# Install Oracle Instant Client
RUN wget https://download.oracle.com/otn_software/linux/instantclient/instantclient-basic-linux.x64-21.8.0.0.0dbru.zip \
    && unzip instantclient-basic-linux.x64-21.8.0.0.0dbru.zip \
    && mv instantclient_21_8 /opt/oracle/ \
    && rm instantclient-basic-linux.x64-21.8.0.0.0dbru.zip

ENV LD_LIBRARY_PATH=/opt/oracle/instantclient_21_8:$LD_LIBRARY_PATH

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create uploads directory
RUN mkdir -p uploads && chmod 755 uploads

EXPOSE 8000

CMD ["gunicorn", "--config", "gunicorn.conf.py", "app_enhanced:app"]
```

#### 2. Create docker-compose.yml
```yaml
version: '3.8'

services:
  app:
    build: .
    ports:
      - "8000:8000"
    environment:
      - FLASK_ENV=production
      - REDIS_URL=redis://redis:6379/0
      - ORACLE_DSN=oracle:1521/XE
    volumes:
      - ./uploads:/app/uploads
    depends_on:
      - redis
      - oracle
    restart: unless-stopped

  redis:
    image: redis:7-alpine
    restart: unless-stopped

  oracle:
    image: container-registry.oracle.com/database/express:21.3.0-xe
    environment:
      - ORACLE_PWD=YourPassword123
    ports:
      - "1521:1521"
    volumes:
      - oracle_data:/opt/oracle/oradata
    restart: unless-stopped

  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf
      - ./ssl:/etc/nginx/ssl
    depends_on:
      - app
    restart: unless-stopped

volumes:
  oracle_data:
```

#### 3. Deploy with Docker
```bash
# Build and start services
docker-compose up -d

# Check logs
docker-compose logs -f app

# Scale if needed
docker-compose up -d --scale app=3
```

## SSL Certificate Setup

### Using Let's Encrypt (Recommended)
```bash
# Install Certbot
sudo apt install certbot python3-certbot-nginx

# Obtain certificate
sudo certbot --nginx -d yourdomain.com

# Auto-renewal
sudo crontab -e
# Add: 0 12 * * * /usr/bin/certbot renew --quiet
```

## Performance Optimization

### 1. Redis Configuration
Edit `/etc/redis/redis.conf`:
```conf
maxmemory 256mb
maxmemory-policy allkeys-lru
save 900 1
save 300 10
save 60 10000
```

### 2. Oracle Database Tuning
```sql
-- Increase shared pool size
ALTER SYSTEM SET shared_pool_size=256M SCOPE=SPFILE;

-- Optimize for file operations
ALTER SYSTEM SET db_file_multiblock_read_count=16 SCOPE=SPFILE;

-- Restart database for changes to take effect
SHUTDOWN IMMEDIATE;
STARTUP;
```

### 3. Application Caching
The application includes built-in caching for:
- File metadata
- User sessions
- Static assets
- API responses

## Monitoring and Maintenance

### 1. Log Management
```bash
# Application logs
tail -f /var/log/securecloud/app.log

# Nginx logs
tail -f /var/log/nginx/access.log
tail -f /var/log/nginx/error.log

# System logs
journalctl -u securecloud -f
```

### 2. Health Checks
Create monitoring endpoints:
- `/health` - Application health
- `/metrics` - Performance metrics
- `/api/status` - System status

### 3. Backup Strategy
```bash
# Database backup
expdp username/password@database directory=backup_dir dumpfile=securecloud_backup.dmp

# File backup
rsync -av /var/www/securecloud/uploads/ /backup/uploads/

# Configuration backup
tar -czf config_backup.tar.gz /etc/nginx/ /etc/systemd/system/securecloud.service .env
```

## Security Hardening

### 1. Firewall Configuration
```bash
# UFW setup
sudo ufw allow ssh
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw enable
```

### 2. Fail2Ban Setup
```bash
# Install and configure Fail2Ban
sudo apt install fail2ban

# Create jail for SecureCloud
sudo tee /etc/fail2ban/jail.d/securecloud.conf << EOF
[securecloud]
enabled = true
port = http,https
filter = securecloud
logpath = /var/log/securecloud/app.log
maxretry = 5
bantime = 3600
EOF
```

### 3. Regular Security Updates
```bash
# Automated security updates
sudo apt install unattended-upgrades
sudo dpkg-reconfigure -plow unattended-upgrades
```

## Troubleshooting

### Common Issues

1. **Oracle Connection Issues**
   - Check LD_LIBRARY_PATH
   - Verify Oracle service status
   - Test connection with sqlplus

2. **WebSocket Connection Failures**
   - Check Nginx proxy configuration
   - Verify Redis connectivity
   - Review firewall settings

3. **File Upload Issues**
   - Check disk space
   - Verify upload directory permissions
   - Review client_max_body_size in Nginx

4. **Performance Issues**
   - Monitor Redis memory usage
   - Check Oracle database performance
   - Review application logs for bottlenecks

### Support
For technical support and updates, refer to the project documentation and issue tracker.

## Production Checklist

- [ ] Environment variables configured
- [ ] Database schema created and migrated
- [ ] SSL certificates installed
- [ ] Firewall configured
- [ ] Monitoring setup
- [ ] Backup strategy implemented
- [ ] Security hardening applied
- [ ] Performance optimization completed
- [ ] Health checks configured
- [ ] Documentation updated

Your SecureCloud platform is now ready for production deployment! 🚀
