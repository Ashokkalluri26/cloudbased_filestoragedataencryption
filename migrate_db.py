#!/usr/bin/env python3
"""
Database migration script to add new encrypted columns to existing SQLite database.
This script will safely add the new columns without losing existing data.
"""

import sqlite3
import os
from datetime import datetime

def migrate_database(db_path='instance/secure_storage.db'):
    """Migrate the database to add new encrypted columns"""
    
    if not os.path.exists(os.path.dirname(db_path)):
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    print(f"Starting database migration at {datetime.now()}")
    
    try:
        # Check if users table exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users'")
        if not cursor.fetchone():
            print("Users table doesn't exist. Creating fresh database schema...")
            create_fresh_schema(cursor)
        else:
            print("Users table exists. Checking for new columns...")
            migrate_users_table(cursor)
            migrate_file_records_table(cursor)
            migrate_activity_logs_table(cursor)
            migrate_share_links_table(cursor)
        
        conn.commit()
        print("Database migration completed successfully!")
        
    except Exception as e:
        conn.rollback()
        print(f"Migration failed: {e}")
        raise
    finally:
        conn.close()

def create_fresh_schema(cursor):
    """Create fresh database schema with all new columns"""
    
    # Users table with encrypted fields
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username VARCHAR(80) UNIQUE NOT NULL,
            email TEXT NOT NULL,
            password_hash VARCHAR(255) NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            two_factor_secret TEXT,
            two_factor_enabled BOOLEAN DEFAULT FALSE,
            private_key TEXT,
            public_key TEXT
        )
    ''')
    
    # File records with encrypted fields
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS file_records (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT NOT NULL,
            stored_filename VARCHAR(255) NOT NULL,
            user_id INTEGER NOT NULL,
            file_size INTEGER NOT NULL,
            encryption_key TEXT NOT NULL,
            upload_date DATETIME DEFAULT CURRENT_TIMESTAMP,
            file_hash VARCHAR(64),
            content_type TEXT,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    # Activity logs with encrypted fields
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS activity_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            action VARCHAR(50) NOT NULL,
            description TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            ip_address TEXT,
            user_agent TEXT,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    # Share links with enhanced features
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS share_links (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            token VARCHAR(64) UNIQUE NOT NULL,
            file_id INTEGER NOT NULL,
            created_by INTEGER NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            expires_at DATETIME NOT NULL,
            downloads INTEGER DEFAULT 0,
            max_downloads INTEGER DEFAULT 0,
            password_hash TEXT,
            access_log TEXT,
            FOREIGN KEY (file_id) REFERENCES file_records (id),
            FOREIGN KEY (created_by) REFERENCES users (id)
        )
    ''')
    
    print("Fresh database schema created successfully!")

def migrate_users_table(cursor):
    """Add new columns to users table if they don't exist"""
    
    # Get existing columns
    cursor.execute("PRAGMA table_info(users)")
    existing_columns = [column[1] for column in cursor.fetchall()]
    
    new_columns = [
        ('private_key', 'TEXT'),
        ('public_key', 'TEXT')
    ]
    
    for column_name, column_type in new_columns:
        if column_name not in existing_columns:
            cursor.execute(f'ALTER TABLE users ADD COLUMN {column_name} {column_type}')
            print(f"Added column '{column_name}' to users table")
    
    # Check if email column needs to be changed to TEXT for encryption
    cursor.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='users'")
    schema = cursor.fetchone()[0]
    if 'email VARCHAR' in schema:
        print("Email column type needs updating for encryption support...")
        # SQLite doesn't support ALTER COLUMN, so we'll handle this in the app

def migrate_file_records_table(cursor):
    """Add new columns to file_records table if they don't exist"""
    
    cursor.execute("PRAGMA table_info(file_records)")
    existing_columns = [column[1] for column in cursor.fetchall()]
    
    new_columns = [
        ('file_hash', 'VARCHAR(64)'),
        ('content_type', 'TEXT')
    ]
    
    for column_name, column_type in new_columns:
        if column_name not in existing_columns:
            cursor.execute(f'ALTER TABLE file_records ADD COLUMN {column_name} {column_type}')
            print(f"Added column '{column_name}' to file_records table")

def migrate_activity_logs_table(cursor):
    """Add new columns to activity_logs table if they don't exist"""
    
    cursor.execute("PRAGMA table_info(activity_logs)")
    existing_columns = [column[1] for column in cursor.fetchall()]
    
    new_columns = [
        ('ip_address', 'TEXT'),
        ('user_agent', 'TEXT')
    ]
    
    for column_name, column_type in new_columns:
        if column_name not in existing_columns:
            cursor.execute(f'ALTER TABLE activity_logs ADD COLUMN {column_name} {column_type}')
            print(f"Added column '{column_name}' to activity_logs table")

def migrate_share_links_table(cursor):
    """Add new columns to share_links table if they don't exist"""
    
    cursor.execute("PRAGMA table_info(share_links)")
    existing_columns = [column[1] for column in cursor.fetchall()]
    
    new_columns = [
        ('max_downloads', 'INTEGER DEFAULT 0'),
        ('password_hash', 'TEXT'),
        ('access_log', 'TEXT')
    ]
    
    for column_name, column_type in new_columns:
        if column_name not in existing_columns:
            cursor.execute(f'ALTER TABLE share_links ADD COLUMN {column_name} {column_type}')
            print(f"Added column '{column_name}' to share_links table")

def run_migration():
    """Run the migration and print results"""
    try:
        migrate_database()
        print("Migration completed successfully!")
        return True
    except Exception as e:
        print(f"Migration failed: {e}")
        return False

if __name__ == '__main__':
    run_migration()
