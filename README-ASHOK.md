# Secure File Storage Platform

A Flask-based cloud file storage platform with AES-256 encryption, Oracle Database integration, and comprehensive security features.

## Features

- **User Authentication**: Secure signup/login with password hashing
- **File Encryption**: AES-256 encryption for all uploaded files
- **Two-Factor Authentication**: TOTP-based 2FA for enhanced security
- **Secure File Sharing**: Generate expiring shareable links
- **Activity Logging**: Track all user actions and file operations
- **Oracle Database**: Robust database backend for metadata storage
- **Modern UI**: Clean, responsive dashboard with Bootstrap

## Prerequisites

- Python 3.8+
- Oracle Database (11g or higher)
- Oracle Instant Client

## Installation

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd majorproject
   ```

2. **Install Python dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Set up Oracle Database**
   - Install Oracle Database locally
   - Create a user/schema for the application
   - Run the schema creation script:
   ```sql
   sqlplus your_username/your_password@localhost:1521/XE @oracle_schema.sql
   ```

4. **Configure environment variables**
   ```bash
   cp .env.example .env
   ```
   Edit `.env` with your configuration:
   ```
   ORACLE_USER=your_oracle_username
   ORACLE_PASSWORD=your_oracle_password
   ORACLE_DSN=localhost:1521/XE
   SECRET_KEY=your-super-secret-key-change-this-in-production
   ```

5. **Create upload directory**
   ```bash
   mkdir uploads
   ```

## Running the Application

1. **Start the Flask application**
   ```bash
   python app.py
   ```

2. **Access the application**
   - Open your browser to `http://localhost:5000`
   - Register a new account or login

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `ORACLE_USER` | Oracle database username | Required |
| `ORACLE_PASSWORD` | Oracle database password | Required |
| `ORACLE_DSN` | Oracle database DSN | Required |
| `SECRET_KEY` | Flask secret key | Required |
| `UPLOAD_FOLDER` | File upload directory | `uploads` |
| `MAX_CONTENT_LENGTH` | Max file size in bytes | `104857600` (100MB) |

### Database Configuration

The application uses SQLAlchemy with Oracle dialect. Ensure your Oracle database is running and accessible with the provided credentials.

## Security Features

### File Encryption
- All files are encrypted using AES-256 before storage
- Each file has a unique encryption key
- Keys are stored securely in the database
- Zero-knowledge architecture - server cannot decrypt files without user access

### Authentication
- Password hashing using Werkzeug's secure methods
- Session-based authentication with Flask-Login
- Optional two-factor authentication using TOTP

### File Sharing
- Secure token-based file sharing
- Configurable expiration times
- Activity logging for all share operations

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Home page |
| `/register` | GET/POST | User registration |
| `/login` | GET/POST | User login |
| `/logout` | GET | User logout |
| `/dashboard` | GET | User dashboard |
| `/upload` | POST | File upload |
| `/download/<id>` | GET | File download |
| `/delete/<id>` | DELETE | File deletion |
| `/share/<id>` | GET | Create share link |
| `/shared/<token>` | GET | Download shared file |
| `/setup-2fa` | GET | 2FA setup page |
| `/enable-2fa` | POST | Enable 2FA |

## File Structure

```
majorproject/
├── app.py                 # Main Flask application
├── models.py             # Database models
├── forms.py              # WTForms definitions
├── encryption.py         # Encryption utilities
├── oracle_schema.sql     # Database schema
├── requirements.txt      # Python dependencies
├── .env.example         # Environment template
├── templates/           # Jinja2 templates
│   ├── base.html
│   ├── index.html
│   ├── dashboard.html
│   ├── login.html
│   ├── register.html
│   ├── two_factor.html
│   └── setup_2fa.html
├── static/              # Static assets
│   ├── css/
│   │   └── style.css
│   └── js/
│       └── main.js
└── uploads/             # File storage directory
```

## Deployment

### Production Considerations

1. **Security**
   - Use strong, unique secret keys
   - Enable HTTPS in production
   - Configure proper firewall rules
   - Regular security updates

2. **Database**
   - Use connection pooling
   - Regular backups
   - Monitor performance

3. **File Storage**
   - Consider cloud storage integration
   - Implement file size limits
   - Regular cleanup of temporary files

### Docker Deployment (Optional)

Create a `Dockerfile`:
```dockerfile
FROM python:3.9-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .
EXPOSE 5000

CMD ["python", "app.py"]
```

## Troubleshooting

### Common Issues

1. **Oracle Connection Error**
   - Verify Oracle database is running
   - Check connection credentials
   - Ensure Oracle Instant Client is installed

2. **File Upload Fails**
   - Check upload directory permissions
   - Verify file size limits
   - Check available disk space

3. **2FA Setup Issues**
   - Ensure system time is synchronized
   - Verify authenticator app compatibility

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

This project is licensed under the MIT License.

## Support

For issues and questions, please create an issue in the repository or contact the development team.
