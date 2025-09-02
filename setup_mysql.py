#!/usr/bin/env python3
"""
MySQL Database Setup Script
Creates database and all required tables for secure cloud storage platform
"""

import mysql.connector
import os
from mysql.connector import Error

def create_database_and_tables():
    """Create MySQL database and all required tables"""
    
    # MySQL connection parameters
    config = {
        'host': 'localhost',
        'user': 'root',
        'password': 'Ash@123uma',
        'port': 3306
    }
    
    try:
        # Connect to MySQL server
        print("Connecting to MySQL server...")
        connection = mysql.connector.connect(**config)
        cursor = connection.cursor()
        
        # Create database
        print("Creating database 'secure_storage'...")
        cursor.execute("CREATE DATABASE IF NOT EXISTS secure_storage")
        print("✓ Database 'secure_storage' created successfully")
        
        # Use the database
        cursor.execute("USE secure_storage")
        
        # Create users table
        print("Creating 'users' table...")
        users_table = """
        CREATE TABLE IF NOT EXISTS users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(80) UNIQUE NOT NULL,
            email TEXT NOT NULL,
            password_hash VARCHAR(255) NOT NULL,
            profile_picture VARCHAR(100) DEFAULT NULL,
            bio TEXT DEFAULT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            last_login DATETIME DEFAULT NULL,
            is_active BOOLEAN DEFAULT TRUE,
            two_factor_enabled BOOLEAN DEFAULT FALSE,
            two_factor_secret VARCHAR(32) DEFAULT NULL,
            INDEX idx_username (username),
            INDEX idx_created_at (created_at)
        )
        """
        cursor.execute(users_table)
        print("✓ Users table created successfully")
        
        # Create file_records table
        print("Creating 'file_records' table...")
        file_records_table = """
        CREATE TABLE IF NOT EXISTS file_records (
            id INT AUTO_INCREMENT PRIMARY KEY,
            filename TEXT NOT NULL,
            stored_filename VARCHAR(255) NOT NULL,
            user_id INT NOT NULL,
            file_size BIGINT NOT NULL,
            encryption_key TEXT NOT NULL,
            upload_date DATETIME DEFAULT CURRENT_TIMESTAMP,
            file_hash VARCHAR(64) DEFAULT NULL,
            content_type TEXT DEFAULT NULL,
            category VARCHAR(50) DEFAULT NULL,
            tags TEXT DEFAULT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            INDEX idx_user_id (user_id),
            INDEX idx_upload_date (upload_date),
            INDEX idx_category (category),
            INDEX idx_file_hash (file_hash)
        )
        """
        cursor.execute(file_records_table)
        print("✓ File records table created successfully")
        
        # Create activity_logs table
        print("Creating 'activity_logs' table...")
        activity_logs_table = """
        CREATE TABLE IF NOT EXISTS activity_logs (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT NOT NULL,
            action VARCHAR(50) NOT NULL,
            description TEXT DEFAULT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            ip_address TEXT DEFAULT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            INDEX idx_user_id (user_id),
            INDEX idx_action (action),
            INDEX idx_timestamp (timestamp)
        )
        """
        cursor.execute(activity_logs_table)
        print("✓ Activity logs table created successfully")
        
        # Create share_links table
        print("Creating 'share_links' table...")
        share_links_table = """
        CREATE TABLE IF NOT EXISTS share_links (
            id INT AUTO_INCREMENT PRIMARY KEY,
            token VARCHAR(64) UNIQUE NOT NULL,
            file_id INT NOT NULL,
            created_by INT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            expires_at DATETIME NOT NULL,
            access_count INT DEFAULT 0,
            max_access INT DEFAULT NULL,
            is_active BOOLEAN DEFAULT TRUE,
            FOREIGN KEY (file_id) REFERENCES file_records(id) ON DELETE CASCADE,
            FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE CASCADE,
            INDEX idx_token (token),
            INDEX idx_file_id (file_id),
            INDEX idx_created_by (created_by),
            INDEX idx_expires_at (expires_at)
        )
        """
        cursor.execute(share_links_table)
        print("✓ Share links table created successfully")
        
        # Create additional indexes for performance
        print("Creating additional indexes...")
        try:
            cursor.execute("CREATE INDEX idx_users_email ON users(email(100))")
            cursor.execute("CREATE INDEX idx_file_records_stored_filename ON file_records(stored_filename)")
            cursor.execute("CREATE INDEX idx_share_links_active_expires ON share_links(is_active, expires_at)")
            print("✓ Additional indexes created successfully")
        except Error as e:
            if "Duplicate key name" in str(e):
                print("✓ Indexes already exist")
            else:
                print(f"Warning: Could not create some indexes: {e}")
        
        # Commit changes
        connection.commit()
        print("\n🎉 MySQL database setup completed successfully!")
        print("Database: secure_storage")
        print("Tables created: users, file_records, activity_logs, share_links")
        print("All indexes and foreign keys configured")
        
        # Show table status
        cursor.execute("SHOW TABLES")
        tables = cursor.fetchall()
        print(f"\nTables in database: {[table[0] for table in tables]}")
        
    except Error as e:
        print(f"❌ Error: {e}")
        return False
        
    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()
            print("MySQL connection closed")
    
    return True

if __name__ == "__main__":
    print("MySQL Database Setup for Secure Cloud Storage Platform")
    print("=" * 60)
    
    success = create_database_and_tables()
    
    if success:
        print("\n✅ Setup completed! You can now run the application with:")
        print("python app_mysql.py")
    else:
        print("\n❌ Setup failed! Please check your MySQL configuration.")
