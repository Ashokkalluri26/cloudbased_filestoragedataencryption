from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime
from encryption import encrypt_sensitive_data, decrypt_sensitive_data

db = SQLAlchemy()

class EncryptedField:
    """Custom field type for encrypted database storage"""
    
    def __init__(self, field_type):
        self.field_type = field_type
    
    def process_bind_param(self, value, dialect):
        if value is not None:
            return encrypt_sensitive_data(str(value))
        return value
    
    def process_result_value(self, value, dialect):
        if value is not None:
            try:
                return decrypt_sensitive_data(value)
            except:
                return value  # Return original if decryption fails
        return value

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.Text, nullable=False)  # Encrypted email
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    two_factor_secret = db.Column(db.Text)  # Encrypted 2FA secret
    two_factor_enabled = db.Column(db.Boolean, default=False)
    private_key = db.Column(db.Text)  # Encrypted RSA private key
    public_key = db.Column(db.Text)  # RSA public key (not encrypted)
    bio = db.Column(db.Text)  # Encrypted user bio
    last_login = db.Column(db.DateTime)
    profile_picture = db.Column(db.String(255))  # Profile picture filename
    subscription_type = db.Column(db.String(20), default='free')  # 'free', 'premium'
    subscription_expires = db.Column(db.DateTime)  # When premium expires
    files_uploaded = db.Column(db.Integer, default=0)  # Track file count
    
    files = db.relationship('FileRecord', backref='owner', lazy=True, cascade='all, delete-orphan')
    activities = db.relationship('ActivityLog', backref='user', lazy=True, cascade='all, delete-orphan')
    share_links = db.relationship('ShareLink', backref='creator', lazy=True, cascade='all, delete-orphan')
    
    def set_email(self, email):
        """Set encrypted email"""
        self.email = encrypt_sensitive_data(email)
    
    def get_email(self):
        """Get decrypted email"""
        try:
            return decrypt_sensitive_data(self.email)
        except:
            return self.email
    
    def set_two_factor_secret(self, secret):
        """Set encrypted 2FA secret"""
        self.two_factor_secret = encrypt_sensitive_data(secret)
    
    def get_two_factor_secret(self):
        """Get decrypted 2FA secret"""
        try:
            return decrypt_sensitive_data(self.two_factor_secret)
        except:
            return self.two_factor_secret
    
    def set_bio(self, bio):
        """Set encrypted bio"""
        if bio:
            self.bio = encrypt_sensitive_data(bio)
        else:
            self.bio = None
    
    def get_bio(self):
        """Get decrypted bio"""
        if self.bio:
            try:
                return decrypt_sensitive_data(self.bio)
            except:
                return self.bio
        return ""
    
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

class FileRecord(db.Model):
    __tablename__ = 'file_records'
    
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.Text, nullable=False)  # Encrypted filename
    stored_filename = db.Column(db.String(255), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    file_size = db.Column(db.Integer, nullable=False)
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
        import json
        self.tags = json.dumps(tags_list) if tags_list else None
    
    def get_tags(self):
        """Get tags as list"""
        import json
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
    user_agent = db.Column(db.Text)  # Encrypted user agent
    
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
    downloads = db.Column(db.Integer, default=0)
    max_downloads = db.Column(db.Integer, default=0)  # 0 = unlimited
    password_hash = db.Column(db.Text)  # Optional password protection
    access_log = db.Column(db.Text)  # Encrypted access log
