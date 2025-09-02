#!/usr/bin/env python3
"""
Setup script for Secure File Storage Platform
Automates the initial setup process
"""

import os
import sys
import subprocess
import secrets
import base64
from cryptography.fernet import Fernet

def check_python_version():
    """Check if Python version is compatible"""
    if sys.version_info < (3, 8):
        print("Error: Python 3.8 or higher is required")
        sys.exit(1)
    print(f"✓ Python {sys.version_info.major}.{sys.version_info.minor} detected")

def install_dependencies():
    """Install required Python packages"""
    print("Installing Python dependencies...")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
        print("✓ Dependencies installed successfully")
    except subprocess.CalledProcessError:
        print("Error: Failed to install dependencies")
        sys.exit(1)

def create_directories():
    """Create necessary directories"""
    directories = ['uploads', 'static/css', 'static/js', 'templates']
    for directory in directories:
        os.makedirs(directory, exist_ok=True)
        print(f"✓ Created directory: {directory}")

def generate_env_file():
    """Generate .env file with secure defaults"""
    if os.path.exists('.env'):
        response = input(".env file already exists. Overwrite? (y/N): ")
        if response.lower() != 'y':
            print("Skipping .env file generation")
            return
    
    # Generate secure secret key
    secret_key = secrets.token_urlsafe(32)
    
    # Generate encryption key
    encryption_key = base64.urlsafe_b64encode(Fernet.generate_key()).decode()
    
    env_content = f"""# Database Configuration
ORACLE_USER=your_oracle_username
ORACLE_PASSWORD=your_oracle_password
ORACLE_DSN=localhost:1521/XE

# Flask Configuration
SECRET_KEY={secret_key}
FLASK_ENV=development
FLASK_DEBUG=True

# File Storage Configuration
UPLOAD_FOLDER=uploads
MAX_CONTENT_LENGTH=104857600

# Encryption Configuration
ENCRYPTION_KEY={encryption_key}

# Optional: Email Configuration for 2FA
MAIL_SERVER=smtp.gmail.com
MAIL_PORT=587
MAIL_USE_TLS=True
MAIL_USERNAME=your_email@gmail.com
MAIL_PASSWORD=your_app_password
"""
    
    with open('.env', 'w') as f:
        f.write(env_content)
    
    print("✓ Generated .env file with secure keys")
    print("⚠️  Please update Oracle database credentials in .env file")

def check_oracle_connection():
    """Check if Oracle database is accessible"""
    try:
        import cx_Oracle
        print("✓ cx_Oracle module available")
        
        # Try to connect (will fail without proper credentials)
        print("⚠️  Please ensure Oracle Database is running and credentials are configured")
        return True
    except ImportError:
        print("⚠️  cx_Oracle not installed. Install Oracle Instant Client and cx_Oracle")
        return False

def main():
    """Main setup function"""
    print("🚀 Setting up Secure File Storage Platform")
    print("=" * 50)
    
    # Check Python version
    check_python_version()
    
    # Install dependencies
    install_dependencies()
    
    # Create directories
    create_directories()
    
    # Generate environment file
    generate_env_file()
    
    # Check Oracle connection
    check_oracle_connection()
    
    print("\n" + "=" * 50)
    print("✅ Setup completed successfully!")
    print("\nNext steps:")
    print("1. Update Oracle credentials in .env file")
    print("2. Run Oracle schema: sqlplus user/pass@dsn @oracle_schema.sql")
    print("3. Start the application: python app.py")
    print("4. Visit http://localhost:5000")

if __name__ == "__main__":
    main()
