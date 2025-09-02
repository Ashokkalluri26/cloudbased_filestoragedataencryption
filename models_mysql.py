#!/usr/bin/env python3
"""
MySQL database models for secure cloud storage platform
Enhanced with AI categorization features
"""

from flask_login import UserMixin
from datetime import datetime, timezone
from encryption import encrypt_sensitive_data, decrypt_sensitive_data
import json

# db will be imported later to avoid circular imports
db = None

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.Text, nullable=False)  # Encrypted email
    password_hash = db.Column(db.String(255), nullable=False)
    profile_picture = db.Column(db.String(100), nullable=True)
    bio = db.Column(db.Text)  # Encrypted bio
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    is_active = db.Column(db.Boolean, default=True)
    
    # Two-factor authentication
    two_factor_enabled = db.Column(db.Boolean, default=False)
    two_factor_secret = db.Column(db.String(32))
    
    # Relationships
    files = db.relationship('FileRecord', backref='user', lazy=True, cascade='all, delete-orphan')
    activity_logs = db.relationship('ActivityLog', backref='user', lazy=True, cascade='all, delete-orphan')
    
    def set_email(self, email):
        """Set encrypted email"""
        self.email = encrypt_sensitive_data(email)
    
    def get_email(self):
        """Get decrypted email"""
        try:
            return decrypt_sensitive_data(self.email)
        except:
            return self.email
    
    def set_bio(self, bio):
        """Set encrypted bio"""
        if bio:
            self.bio = encrypt_sensitive_data(bio)
        else:
            self.bio = None
    
    def get_bio(self):
        """Get decrypted bio"""
        if not self.bio:
            return ""
        try:
            return decrypt_sensitive_data(self.bio)
        except:
            return self.bio

class FileRecord(db.Model):
    __tablename__ = 'file_records'
    
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.Text, nullable=False)  # Encrypted filename
    stored_filename = db.Column(db.String(255), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    file_size = db.Column(db.BigInteger, nullable=False)
    encryption_key = db.Column(db.Text, nullable=False)  # Double encrypted
    upload_date = db.Column(db.DateTime, default=datetime.utcnow)
    file_hash = db.Column(db.String(64))  # SHA-256 hash for integrity
    content_type = db.Column(db.Text)  # Encrypted content type
    category = db.Column(db.String(50))  # AI-generated category
    tags = db.Column(db.Text)  # JSON string of AI-generated tags
    
    share_links = db.relationship('ShareLink', backref='file', lazy=True, cascade='all, delete-orphan')
    
    def set_filename(self, filename):
        """Set encrypted filename"""
        self.filename = encrypt_sensitive_data(filename)
    
    def get_filename(self):
        """Get decrypted filename"""
        try:
            return decrypt_sensitive_data(self.filename)
        except:
            return self.filename
    
    def set_content_type(self, content_type):
        """Set encrypted content type"""
        self.content_type = encrypt_sensitive_data(content_type)
    
    def get_content_type(self):
        """Get decrypted content type"""
        try:
            return decrypt_sensitive_data(self.content_type)
        except:
            return self.content_type
    
    def set_tags(self, tags_list):
        """Set tags as JSON string"""
        self.tags = json.dumps(tags_list) if tags_list else None
    
    def get_tags(self):
        """Get tags as list"""
        try:
            return json.loads(self.tags) if self.tags else []
        except:
            return []

class ActivityLog(db.Model):
    __tablename__ = 'activity_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    action = db.Column(db.String(50), nullable=False)
    description = db.Column(db.Text)  # Encrypted sensitive descriptions
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    ip_address = db.Column(db.Text)  # Encrypted IP address
    
    def set_description(self, description):
        """Set encrypted description"""
        self.description = encrypt_sensitive_data(description)
    
    def get_description(self):
        """Get decrypted description"""
        try:
            return decrypt_sensitive_data(self.description)
        except:
            return self.description
    
    def set_ip_address(self, ip_address):
        """Set encrypted IP address"""
        self.ip_address = encrypt_sensitive_data(ip_address)
    
    def get_ip_address(self):
        """Get decrypted IP address"""
        try:
            return decrypt_sensitive_data(self.ip_address)
        except:
            return self.ip_address

class ShareLink(db.Model):
    __tablename__ = 'share_links'
    
    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String(64), unique=True, nullable=False)
    file_id = db.Column(db.Integer, db.ForeignKey('file_records.id'), nullable=False)
    created_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    access_count = db.Column(db.Integer, default=0)
    max_access = db.Column(db.Integer, default=None)  # None = unlimited
    is_active = db.Column(db.Boolean, default=True)
    
    def is_expired(self):
        """Check if share link is expired"""
        return datetime.utcnow() > self.expires_at
    
    def is_access_exceeded(self):
        """Check if access limit is exceeded"""
        if self.max_access is None:
            return False
        return self.access_count >= self.max_access
    
    def can_access(self):
        """Check if share link can be accessed"""
        return self.is_active and not self.is_expired() and not self.is_access_exceeded()
