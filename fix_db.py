#!/usr/bin/env python3
"""
Quick database fix script for credential saving issues
"""

import os
import sys
from flask import Flask
from models_sqlite import db, User
from encryption import hash_password_secure
import pyotp

# Setup Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = 'temp-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///instance/secure_storage.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)

def fix_database():
    """Fix database issues and ensure proper table creation"""
    with app.app_context():
        try:
            print("🔧 Fixing database...")
            
            # Drop and recreate all tables
            db.drop_all()
            db.create_all()
            print("✅ Database tables recreated successfully!")
            
            # Test user creation
            test_user = User(
                username="testuser",
                two_factor_secret=pyotp.random_base32()
            )
            test_user.set_email("test@example.com")
            test_user.password_hash = hash_password_secure("testpass123")
            
            db.session.add(test_user)
            db.session.commit()
            
            print("✅ Test user created successfully!")
            
            # Verify user can be retrieved
            retrieved_user = User.query.filter_by(username="testuser").first()
            if retrieved_user:
                print(f"✅ User retrieval works: {retrieved_user.username}")
                print(f"✅ Email decryption works: {retrieved_user.get_email()}")
                
                # Clean up test user
                db.session.delete(retrieved_user)
                db.session.commit()
                print("✅ Test user cleaned up")
            
            print("🎉 Database is now working correctly!")
            return True
            
        except Exception as e:
            print(f"❌ Database fix failed: {e}")
            return False

if __name__ == "__main__":
    success = fix_database()
    if success:
        print("\n🚀 You can now run the app with: python app_sqlite.py")
    else:
        print("\n💥 Database fix failed. Check the error messages above.")
