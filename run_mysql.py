#!/usr/bin/env python3
"""
MySQL Application Launcher for Secure File Storage Platform
"""

import os
import sys
from dotenv import load_dotenv

def check_mysql_environment():
    """Check if MySQL environment is properly configured"""
    load_dotenv('.env.mysql')
    
    required_vars = ['MYSQL_HOST', 'MYSQL_USER', 'MYSQL_PASSWORD', 'MYSQL_DATABASE', 'SECRET_KEY']
    missing_vars = []
    
    for var in required_vars:
        if not os.getenv(var):
            missing_vars.append(var)
    
    if missing_vars:
        print("❌ Missing MySQL environment variables:")
        for var in missing_vars:
            print(f"   - {var}")
        print("\nPlease update your .env.mysql file with the required values.")
        return False
    
    print("✅ MySQL environment configuration looks good!")
    return True

def create_directories():
    """Create necessary directories"""
    dirs = ['uploads', 'static/css', 'static/js', 'templates']
    for directory in dirs:
        os.makedirs(directory, exist_ok=True)
    print("✅ Directories created successfully!")

def main():
    """Main function"""
    print("🚀 Starting Secure File Storage Platform with MySQL")
    print("=" * 60)
    
    # Create directories
    create_directories()
    
    # Check environment
    if not check_mysql_environment():
        print("\n📝 To fix this:")
        print("1. Update .env.mysql with your MySQL credentials")
        print("2. Ensure MySQL server is running")
        print("3. Run this script again")
        return
    
    print("\n🗄️  MySQL Database Setup:")
    print("1. Ensure MySQL server is running")
    print("2. Database 'secure_storage' will be created automatically")
    
    print("\n🌐 Starting Flask Application with MySQL...")
    
    # Import and run the MySQL app
    try:
        from app_mysql import app
        print("✅ MySQL Flask app loaded successfully!")
        print("\n🎉 Application starting at http://localhost:5000")
        print("📊 Files will be stored in MySQL database")
        print("Press Ctrl+C to stop the server")
        app.run(debug=True, host='0.0.0.0', port=5000)
    except Exception as e:
        print(f"❌ Error starting MySQL application: {e}")
        print("\nPlease check:")
        print("- MySQL server is running and accessible")
        print("- Database credentials are correct in .env.mysql")
        print("- All dependencies are installed: pip install -r requirements.txt")

if __name__ == "__main__":
    main()
