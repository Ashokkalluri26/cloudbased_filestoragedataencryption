#!/usr/bin/env python3
"""
Database migration script to add AI categorization features
Adds category and tags columns to file_records table
"""

import sqlite3
import os
from datetime import datetime

def migrate_database():
    """Add category and tags columns to file_records table"""
    
    # Database paths to check
    db_paths = [
        'instance/simple.db',
        'instance/simple_new.db', 
        'instance/secure_storage.db'
    ]
    
    for db_path in db_paths:
        if os.path.exists(db_path):
            print(f"Migrating database: {db_path}")
            
            try:
                conn = sqlite3.connect(db_path)
                cursor = conn.cursor()
                
                # Check if columns already exist
                cursor.execute("PRAGMA table_info(file_records)")
                columns = [column[1] for column in cursor.fetchall()]
                
                # Add category column if it doesn't exist
                if 'category' not in columns:
                    cursor.execute("ALTER TABLE file_records ADD COLUMN category VARCHAR(50)")
                    print(f"  ✓ Added 'category' column to {db_path}")
                else:
                    print(f"  - 'category' column already exists in {db_path}")
                
                # Add tags column if it doesn't exist
                if 'tags' not in columns:
                    cursor.execute("ALTER TABLE file_records ADD COLUMN tags TEXT")
                    print(f"  ✓ Added 'tags' column to {db_path}")
                else:
                    print(f"  - 'tags' column already exists in {db_path}")
                
                conn.commit()
                conn.close()
                print(f"  ✓ Migration completed for {db_path}")
                
            except Exception as e:
                print(f"  ✗ Error migrating {db_path}: {str(e)}")
        else:
            print(f"Database not found: {db_path}")
    
    print("\nMigration completed!")

if __name__ == "__main__":
    print("Starting database migration for AI categorization features...")
    print(f"Timestamp: {datetime.now()}")
    print("-" * 60)
    
    migrate_database()
