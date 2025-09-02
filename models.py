from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime
import json

db = SQLAlchemy()

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=True)  # Nullable for passwordless users
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    is_active = db.Column(db.Boolean, default=True)
    storage_quota = db.Column(db.BigInteger, default=5368709120)  # 5GB default
    storage_used = db.Column(db.BigInteger, default=0)
    
    # 2FA settings
    two_factor_secret = db.Column(db.String(32))
    two_factor_enabled = db.Column(db.Boolean, default=False)
    
    # WebAuthn/Passkey settings
    webauthn_enabled = db.Column(db.Boolean, default=False)
    
    # User preferences
    theme_preference = db.Column(db.String(20), default='light')
    high_contrast_mode = db.Column(db.Boolean, default=False)
    notification_preferences = db.Column(db.Text)  # JSON string
    
    # Subscription fields
    profile_picture = db.Column(db.String(255))  # Profile picture filename
    subscription_type = db.Column(db.String(20), default='free')  # 'free', 'premium'
    subscription_expires = db.Column(db.DateTime)  # When premium expires
    files_uploaded = db.Column(db.Integer, default=0)  # Track file count
    
    def can_upload_files(self):
        """Check if user can upload more files"""
        if self.subscription_type == 'premium':
            # Check if premium subscription is still valid
            if self.subscription_expires and self.subscription_expires > datetime.utcnow():
                return True
            else:
                # Premium expired, revert to free
                self.subscription_type = 'free'
                db.session.commit()
        
        # Free users get 50 files max
        return self.files_uploaded < 50
    
    def get_remaining_files(self):
        """Get number of files user can still upload"""
        if self.subscription_type == 'premium' and self.subscription_expires and self.subscription_expires > datetime.utcnow():
            return float('inf')  # Unlimited
        return max(0, 50 - self.files_uploaded)
    
    def increment_file_count(self):
        """Increment user's file count"""
        self.files_uploaded += 1
        db.session.commit()
    
    def decrement_file_count(self):
        """Decrement user's file count when file is deleted"""
        if self.files_uploaded > 0:
            self.files_uploaded -= 1
            db.session.commit()
    
    # Relationships
    files = db.relationship('FileRecord', backref='owner', lazy=True, cascade='all, delete-orphan')
    activities = db.relationship('ActivityLog', backref='user', lazy=True, cascade='all, delete-orphan')
    credentials = db.relationship('WebAuthnCredential', backref='user', lazy=True, cascade='all, delete-orphan')
    sync_sessions = db.relationship('SyncSession', backref='user', lazy=True, cascade='all, delete-orphan')

class WebAuthnCredential(db.Model):
    __tablename__ = 'webauthn_credentials'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    credential_id = db.Column(db.Text, nullable=False, unique=True)
    public_key = db.Column(db.Text, nullable=False)
    sign_count = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_used = db.Column(db.DateTime)
    device_name = db.Column(db.String(100))

class FileRecord(db.Model):
    __tablename__ = 'file_records'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    filename = db.Column(db.String(255), nullable=False)
    file_size = db.Column(db.BigInteger, nullable=False)
    encryption_key = db.Column(db.Text, nullable=False)
    upload_date = db.Column(db.DateTime, default=datetime.utcnow)
    last_accessed = db.Column(db.DateTime)
    
    # File metadata
    mime_type = db.Column(db.String(100))
    file_hash = db.Column(db.String(64))  # SHA-256 hash for integrity
    
    # AI categorization
    category = db.Column(db.String(50))  # document, image, video, audio, etc.
    tags = db.Column(db.Text)  # JSON array of AI-generated tags
    
    # Sync status
    sync_status = db.Column(db.String(20), default='synced')  # synced, pending, failed
    version = db.Column(db.Integer, default=1)
    
    # Relationships
    share_links = db.relationship('ShareLink', backref='file', lazy=True, cascade='all, delete-orphan')
    chunks = db.relationship('FileChunk', backref='file', lazy=True, cascade='all, delete-orphan')

class FileChunk(db.Model):
    __tablename__ = 'file_chunks'
    
    id = db.Column(db.Integer, primary_key=True)
    file_id = db.Column(db.Integer, db.ForeignKey('file_records.id'), nullable=False)
    chunk_number = db.Column(db.Integer, nullable=False)
    chunk_size = db.Column(db.Integer, nullable=False)
    chunk_hash = db.Column(db.String(64), nullable=False)
    upload_status = db.Column(db.String(20), default='pending')  # pending, uploaded, failed

class ActivityLog(db.Model):
    __tablename__ = 'activity_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    action = db.Column(db.String(50), nullable=False)
    description = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.Text)
    session_id = db.Column(db.String(64))
    
    # Security context
    risk_level = db.Column(db.String(10), default='low')  # low, medium, high
    location = db.Column(db.String(100))  # Approximate location

class ShareLink(db.Model):
    __tablename__ = 'share_links'
    
    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String(64), unique=True, nullable=False)
    file_id = db.Column(db.Integer, db.ForeignKey('file_records.id'), nullable=False)
    created_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    downloads = db.Column(db.Integer, default=0)
    max_downloads = db.Column(db.Integer, default=0)  # 0 = unlimited
    
    # Enhanced permissions
    password_protected = db.Column(db.Boolean, default=False)
    password_hash = db.Column(db.String(255))
    allowed_ips = db.Column(db.Text)  # JSON array of allowed IP addresses
    permissions = db.Column(db.String(20), default='download')  # download, view

class SyncSession(db.Model):
    __tablename__ = 'sync_sessions'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    session_id = db.Column(db.String(64), unique=True, nullable=False)
    device_info = db.Column(db.Text)  # JSON with device information
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_sync = db.Column(db.DateTime)
    status = db.Column(db.String(20), default='active')  # active, offline, expired
    
    # Offline queue
    pending_operations = db.Column(db.Text)  # JSON array of pending operations

class SecurityEvent(db.Model):
    __tablename__ = 'security_events'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    event_type = db.Column(db.String(50), nullable=False)
    severity = db.Column(db.String(10), nullable=False)  # low, medium, high, critical
    description = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.Text)
    resolved = db.Column(db.Boolean, default=False)
    
    # Additional context
    event_metadata = db.Column(db.Text)  # JSON with additional event data
