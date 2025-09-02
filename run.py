#!/usr/bin/env python3
"""
Quick start script for Secure File Storage Platform
"""

import os
import sys
from dotenv import load_dotenv

def check_environment():
    """Check if environment is properly configured"""
    load_dotenv()
    
    required_vars = ['ORACLE_USER', 'ORACLE_PASSWORD', 'ORACLE_DSN', 'SECRET_KEY']
    missing_vars = []
    
    for var in required_vars:
        if not os.getenv(var):
            missing_vars.append(var)
    
    if missing_vars:
        print("❌ Missing environment variables:")
        for var in missing_vars:
            print(f"   - {var}")
        print("\nPlease update your .env file with the required values.")
        return False
    
    print("✅ Environment configuration looks good!")
    return True

def create_directories():
    """Create necessary directories"""
    dirs = ['uploads', 'static/css', 'static/js', 'templates']
    for directory in dirs:
        os.makedirs(directory, exist_ok=True)
    print("✅ Directories created successfully!")

def main():
    """Main function"""
    print("🚀 Starting Secure File Storage Platform")
    print("=" * 50)
    
    # Create directories
    create_directories()
    
    # Check environment
    if not check_environment():
        print("\n📝 To fix this:")
        print("1. Copy .env.example to .env")
        print("2. Update Oracle database credentials")
        print("3. Run this script again")
        return
    
    print("\n🗄️  Database Setup:")
    print("1. Ensure Oracle Database is running")
    print("2. Run: sqlplus your_user/your_pass@your_dsn @oracle_schema.sql")
    
    print("\n🌐 Starting Flask Application...")
    
    # Import and run the app
    try:
        from app import app
        print("✅ Flask app loaded successfully!")
        print("\n🎉 Application starting at http://localhost:5000")
        print("Press Ctrl+C to stop the server")
        app.run(debug=True, host='0.0.0.0', port=5000)
    except Exception as e:
        print(f"❌ Error starting application: {e}")
        print("\nPlease check:")
        print("- Oracle database is running and accessible")
        print("- All dependencies are installed: pip install -r requirements.txt")
        print("- Environment variables are properly configured")

if __name__ == "__main__":
    main()
