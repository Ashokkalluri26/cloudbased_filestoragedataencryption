# Deployment Guide - SecureVault

This guide provides step-by-step instructions for deploying SecureVault to production environments.

## 🚀 Quick Start Deployment

### Prerequisites
- Node.js 16+ installed
- MongoDB database (local or Atlas)
- AWS S3 bucket configured
- Domain name (optional but recommended)

### 1. Environment Setup

Create production `.env` file:
```bash
# Production Environment Variables
NODE_ENV=production
PORT=5000

# Database (Use MongoDB Atlas for production)
MONGODB_URI=mongodb+srv://username:password@cluster.mongodb.net/secure-file-storage

# JWT Secret (Generate strong 64-character secret)
JWT_SECRET=your-production-jwt-secret-64-characters-long

# AWS S3 Configuration
AWS_ACCESS_KEY_ID=your-production-aws-access-key
AWS_SECRET_ACCESS_KEY=your-production-aws-secret-key
AWS_REGION=us-east-1
AWS_S3_BUCKET=your-production-bucket-name

# Encryption Key (Generate secure 32-character key)
ENCRYPTION_KEY=your-production-32-character-encryption-key

# Frontend URL
FRONTEND_URL=https://yourdomain.com
```

### 2. Build and Deploy

```bash
# Install dependencies
cd backend && npm ci --production
cd ../frontend && npm ci

# Build frontend
npm run build

# Start production server
cd ../backend && npm start
```

## 🐳 Docker Deployment

### Docker Compose Setup

Create `docker-compose.yml`:
```yaml
version: '3.8'

services:
  backend:
    build: ./backend
    ports:
      - "5000:5000"
    environment:
      - NODE_ENV=production
      - MONGODB_URI=mongodb://mongo:27017/secure-file-storage
      - JWT_SECRET=${JWT_SECRET}
      - AWS_ACCESS_KEY_ID=${AWS_ACCESS_KEY_ID}
      - AWS_SECRET_ACCESS_KEY=${AWS_SECRET_ACCESS_KEY}
      - AWS_REGION=${AWS_REGION}
      - AWS_S3_BUCKET=${AWS_S3_BUCKET}
      - ENCRYPTION_KEY=${ENCRYPTION_KEY}
    depends_on:
      - mongo
    volumes:
      - ./backend:/app
      - /app/node_modules

  frontend:
    build: ./frontend
    ports:
      - "3000:3000"
    depends_on:
      - backend

  mongo:
    image: mongo:5.0
    ports:
      - "27017:27017"
    volumes:
      - mongo_data:/data/db

volumes:
  mongo_data:
```

### Deploy with Docker
```bash
# Build and start services
docker-compose up -d

# View logs
docker-compose logs -f

# Stop services
docker-compose down
```

## ☁️ AWS Deployment

### EC2 Instance Setup

1. **Launch EC2 Instance**
   - Choose Ubuntu 20.04 LTS
   - Instance type: t3.medium or larger
   - Configure security groups (ports 80, 443, 22)

2. **Install Dependencies**
```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install Node.js
curl -fsSL https://deb.nodesource.com/setup_16.x | sudo -E bash -
sudo apt-get install -y nodejs

# Install PM2
sudo npm install -g pm2

# Install Nginx
sudo apt install nginx -y

# Install certbot for SSL
sudo apt install certbot python3-certbot-nginx -y
```

3. **Deploy Application**
```bash
# Clone repository
git clone <your-repo-url>
cd majorproject

# Install backend dependencies
cd backend && npm ci --production

# Install frontend dependencies and build
cd ../frontend && npm ci && npm run build

# Copy build files to Nginx
sudo cp -r build/* /var/www/html/
```

4. **Configure PM2**
```bash
# Create ecosystem file
cat > ecosystem.config.js << EOF
module.exports = {
  apps: [{
    name: 'securevault-backend',
    script: './backend/server.js',
    instances: 'max',
    exec_mode: 'cluster',
    env: {
      NODE_ENV: 'production',
      PORT: 5000
    }
  }]
}
EOF

# Start with PM2
pm2 start ecosystem.config.js
pm2 save
pm2 startup
```

5. **Configure Nginx**
```nginx
# /etc/nginx/sites-available/securevault
server {
    listen 80;
    server_name yourdomain.com;

    # Frontend
    location / {
        root /var/www/html;
        index index.html;
        try_files $uri $uri/ /index.html;
    }

    # Backend API
    location /api {
        proxy_pass http://localhost:5000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_cache_bypass $http_upgrade;
    }
}
```

```bash
# Enable site
sudo ln -s /etc/nginx/sites-available/securevault /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl restart nginx

# Setup SSL
sudo certbot --nginx -d yourdomain.com
```

## 🌐 Heroku Deployment

### Backend Deployment

1. **Prepare for Heroku**
```bash
cd backend

# Create Procfile
echo "web: node server.js" > Procfile

# Update package.json
npm install --save-dev @babel/core @babel/preset-env
```

2. **Deploy to Heroku**
```bash
# Install Heroku CLI and login
heroku login

# Create app
heroku create securevault-backend

# Set environment variables
heroku config:set NODE_ENV=production
heroku config:set JWT_SECRET=your-jwt-secret
heroku config:set AWS_ACCESS_KEY_ID=your-aws-key
heroku config:set AWS_SECRET_ACCESS_KEY=your-aws-secret
heroku config:set AWS_REGION=us-east-1
heroku config:set AWS_S3_BUCKET=your-bucket
heroku config:set ENCRYPTION_KEY=your-encryption-key
heroku config:set MONGODB_URI=your-mongodb-atlas-uri

# Deploy
git add .
git commit -m "Deploy to Heroku"
git push heroku main
```

### Frontend Deployment (Netlify)

1. **Build and Deploy**
```bash
cd frontend

# Update API base URL for production
# In src/contexts/AuthContext.js, update axios baseURL

# Build
npm run build

# Deploy to Netlify (drag and drop build folder)
# Or use Netlify CLI
npm install -g netlify-cli
netlify deploy --prod --dir=build
```

## 🔒 Security Configuration

### SSL Certificate Setup
```bash
# Let's Encrypt with Certbot
sudo certbot --nginx -d yourdomain.com -d www.yourdomain.com

# Auto-renewal
sudo crontab -e
# Add: 0 12 * * * /usr/bin/certbot renew --quiet
```

### Firewall Configuration
```bash
# UFW setup
sudo ufw enable
sudo ufw allow ssh
sudo ufw allow 'Nginx Full'
sudo ufw status
```

### MongoDB Security
```bash
# If using local MongoDB
sudo systemctl enable mongod
sudo systemctl start mongod

# Create admin user
mongo
use admin
db.createUser({
  user: "admin",
  pwd: "secure-password",
  roles: ["userAdminAnyDatabase"]
})
```

## 📊 Monitoring Setup

### PM2 Monitoring
```bash
# Monitor processes
pm2 monit

# View logs
pm2 logs

# Restart app
pm2 restart securevault-backend
```

### Log Rotation
```bash
# Setup log rotation
sudo nano /etc/logrotate.d/securevault

# Add configuration
/var/log/securevault/*.log {
    daily
    missingok
    rotate 52
    compress
    notifempty
    create 644 root root
}
```

## 🔧 Performance Optimization

### Nginx Optimization
```nginx
# Add to nginx.conf
gzip on;
gzip_vary on;
gzip_min_length 1024;
gzip_types text/plain text/css text/xml text/javascript application/javascript application/xml+rss application/json;

# Enable caching
location ~* \.(js|css|png|jpg|jpeg|gif|ico|svg)$ {
    expires 1y;
    add_header Cache-Control "public, immutable";
}
```

### Database Optimization
```javascript
// Add indexes in MongoDB
db.files.createIndex({ "owner": 1, "createdAt": -1 })
db.files.createIndex({ "shareToken": 1 })
db.users.createIndex({ "email": 1 }, { unique: true })
```

## 🚨 Backup Strategy

### Database Backup
```bash
# MongoDB backup script
#!/bin/bash
DATE=$(date +%Y%m%d_%H%M%S)
mongodump --uri="$MONGODB_URI" --out="/backups/mongodb_$DATE"
tar -czf "/backups/mongodb_$DATE.tar.gz" "/backups/mongodb_$DATE"
rm -rf "/backups/mongodb_$DATE"

# Keep only last 7 days
find /backups -name "mongodb_*.tar.gz" -mtime +7 -delete
```

### S3 Backup
```bash
# S3 sync for additional backup
aws s3 sync s3://your-bucket s3://your-backup-bucket --delete
```

## 🔍 Health Checks

### Application Health Check
```javascript
// Add to server.js
app.get('/health', (req, res) => {
  res.json({
    status: 'OK',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    memory: process.memoryUsage()
  });
});
```

### Monitoring Script
```bash
#!/bin/bash
# health-check.sh
HEALTH_URL="https://yourdomain.com/api/health"
RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" $HEALTH_URL)

if [ $RESPONSE -ne 200 ]; then
    echo "Health check failed: $RESPONSE"
    # Send alert (email, Slack, etc.)
fi
```

## 🆘 Troubleshooting

### Common Issues

1. **Port Already in Use**
```bash
sudo lsof -i :5000
sudo kill -9 <PID>
```

2. **Permission Denied**
```bash
sudo chown -R $USER:$USER /path/to/app
chmod +x server.js
```

3. **MongoDB Connection Issues**
```bash
# Check MongoDB status
sudo systemctl status mongod
sudo systemctl restart mongod
```

4. **SSL Certificate Issues**
```bash
sudo certbot renew --dry-run
sudo nginx -t
sudo systemctl reload nginx
```

### Log Locations
- Application logs: `pm2 logs`
- Nginx logs: `/var/log/nginx/`
- System logs: `/var/log/syslog`

## 📋 Deployment Checklist

- [ ] Environment variables configured
- [ ] Database connection tested
- [ ] AWS S3 bucket accessible
- [ ] SSL certificate installed
- [ ] Firewall configured
- [ ] Backup strategy implemented
- [ ] Monitoring setup
- [ ] Health checks working
- [ ] Performance optimized
- [ ] Security hardened

## 🔄 Updates and Maintenance

### Zero-Downtime Deployment
```bash
# Using PM2 for zero-downtime updates
git pull origin main
cd backend && npm ci --production
pm2 reload ecosystem.config.js
```

### Database Migrations
```bash
# Run migration scripts
node migrations/migrate.js
```

This deployment guide ensures your SecureVault application is production-ready with proper security, monitoring, and backup strategies.
