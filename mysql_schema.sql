-- MySQL Schema for Secure Cloud Storage Platform
-- Enhanced with AI categorization features

CREATE DATABASE IF NOT EXISTS secure_storage;
USE secure_storage;

-- Users table
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(80) UNIQUE NOT NULL,
    email TEXT NOT NULL,  -- Encrypted email
    password_hash VARCHAR(255) NOT NULL,
    profile_picture VARCHAR(100) DEFAULT NULL,
    bio TEXT DEFAULT NULL,  -- Encrypted bio
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_login DATETIME DEFAULT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    two_factor_enabled BOOLEAN DEFAULT FALSE,
    two_factor_secret VARCHAR(32) DEFAULT NULL,
    INDEX idx_username (username),
    INDEX idx_created_at (created_at)
);

-- File records table with AI categorization
CREATE TABLE file_records (
    id INT AUTO_INCREMENT PRIMARY KEY,
    filename TEXT NOT NULL,  -- Encrypted filename
    stored_filename VARCHAR(255) NOT NULL,
    user_id INT NOT NULL,
    file_size BIGINT NOT NULL,
    encryption_key TEXT NOT NULL,  -- Double encrypted
    upload_date DATETIME DEFAULT CURRENT_TIMESTAMP,
    file_hash VARCHAR(64) DEFAULT NULL,  -- SHA-256 hash
    content_type TEXT DEFAULT NULL,  -- Encrypted content type
    category VARCHAR(50) DEFAULT NULL,  -- AI-generated category
    tags TEXT DEFAULT NULL,  -- JSON string of AI-generated tags
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_user_id (user_id),
    INDEX idx_upload_date (upload_date),
    INDEX idx_category (category),
    INDEX idx_file_hash (file_hash)
);

-- Activity logs table
CREATE TABLE activity_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    action VARCHAR(50) NOT NULL,
    description TEXT DEFAULT NULL,  -- Encrypted sensitive descriptions
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    ip_address TEXT DEFAULT NULL,  -- Encrypted IP address
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_user_id (user_id),
    INDEX idx_action (action),
    INDEX idx_timestamp (timestamp)
);

-- Share links table
CREATE TABLE share_links (
    id INT AUTO_INCREMENT PRIMARY KEY,
    token VARCHAR(64) UNIQUE NOT NULL,
    file_id INT NOT NULL,
    created_by INT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME NOT NULL,
    access_count INT DEFAULT 0,
    max_access INT DEFAULT NULL,  -- NULL = unlimited
    is_active BOOLEAN DEFAULT TRUE,
    FOREIGN KEY (file_id) REFERENCES file_records(id) ON DELETE CASCADE,
    FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_token (token),
    INDEX idx_file_id (file_id),
    INDEX idx_created_by (created_by),
    INDEX idx_expires_at (expires_at)
);

-- Create indexes for better performance
CREATE INDEX idx_users_email ON users(email(100));
CREATE INDEX idx_file_records_stored_filename ON file_records(stored_filename);
CREATE INDEX idx_share_links_active_expires ON share_links(is_active, expires_at);

-- Insert sample data (optional)
-- INSERT INTO users (username, email, password_hash, two_factor_secret) 
-- VALUES ('admin', 'admin@example.com', 'hashed_password_here', 'base32_secret_here');
