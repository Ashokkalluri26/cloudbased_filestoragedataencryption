-- Direct MySQL commands to create database and tables
-- Run this in MySQL Workbench or command line

-- Create database
CREATE DATABASE IF NOT EXISTS secure_storage;
USE secure_storage;

-- Users table
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
);

-- File records table with AI categorization
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
);

-- Activity logs table
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
);

-- Share links table
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
);

-- Additional indexes for performance
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email(100));
CREATE INDEX IF NOT EXISTS idx_file_records_stored_filename ON file_records(stored_filename);
CREATE INDEX IF NOT EXISTS idx_share_links_active_expires ON share_links(is_active, expires_at);

-- Show created tables
SHOW TABLES;

-- Show table structures
DESCRIBE users;
DESCRIBE file_records;
DESCRIBE activity_logs;
DESCRIBE share_links;
