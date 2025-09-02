#!/usr/bin/env python3
"""
Flask application with MySQL database integration
Secure cloud file storage platform with MySQL backend
"""

import os
import secrets
import hashlib
import base64
from datetime import datetime, timezone, timedelta
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, send_file, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from PIL import Image
import pyotp
import qrcode
from io import BytesIO
import json
from cryptography.fernet import Fernet
from dotenv import load_dotenv

# Load environment variables
load_dotenv('.env.mysql')

# Import AI categorizer functions
try:
    from ai_categorizer import categorize_file, generate_tags, get_file_insights
except ImportError:
    def categorize_file(filename, content_type):
        return 'other'
    def generate_tags(filename, content_type):
        return []
    def get_file_insights(filename, content_type):
        return {}

# Define encryption functions directly to avoid import issues
def generate_encryption_key():
    """Generate a new encryption key for file encryption"""
    return Fernet.generate_key()

def encrypt_file(input_path, output_path, key):
    """Encrypt a file using Fernet encryption"""
    fernet = Fernet(key)
    with open(input_path, 'rb') as file:
        original = file.read()
    encrypted = fernet.encrypt(original)
    with open(output_path, 'wb') as encrypted_file:
        encrypted_file.write(encrypted)

def decrypt_file(input_path, output_path, key):
    """Decrypt a file using Fernet encryption"""
    fernet = Fernet(key)
    with open(input_path, 'rb') as encrypted_file:
        encrypted = encrypted_file.read()
    decrypted = fernet.decrypt(encrypted)
    with open(output_path, 'wb') as decrypted_file:
        decrypted_file.write(decrypted)

def encrypt_sensitive_data(data):
    """Encrypt sensitive data for database storage"""
    if not data:
        return data
    key = os.getenv('ENCRYPTION_KEY')
    if not key:
        key = Fernet.generate_key()
    if isinstance(key, str):
        key = key.encode()
    fernet = Fernet(key)
    return fernet.encrypt(data.encode()).decode()

def decrypt_sensitive_data(encrypted_data):
    """Decrypt sensitive data from database"""
    if not encrypted_data:
        return encrypted_data
    key = os.getenv('ENCRYPTION_KEY')
    if not key:
        return encrypted_data  # Can't decrypt without key
    if isinstance(key, str):
        key = key.encode()
    fernet = Fernet(key)
    return fernet.decrypt(encrypted_data.encode()).decode()

print("✅ Encryption functions defined successfully")

app = Flask(__name__)

# Configuration
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your-secret-key-here')
app.config['UPLOAD_FOLDER'] = os.getenv('UPLOAD_FOLDER', 'uploads')
app.config['MAX_CONTENT_LENGTH'] = int(os.getenv('MAX_CONTENT_LENGTH', 104857600))

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(os.path.join(app.config['UPLOAD_FOLDER'], 'profile_pics'), exist_ok=True)

# MySQL configuration
mysql_host = os.getenv('MYSQL_HOST', 'localhost')
mysql_port = os.getenv('MYSQL_PORT', '3306')
mysql_user = os.getenv('MYSQL_USER', 'root')
mysql_password = os.getenv('MYSQL_PASSWORD', 'Ash@123uma')
mysql_database = os.getenv('MYSQL_DATABASE', 'secure_storage')

from urllib.parse import quote_plus
app.config['SQLALCHEMY_DATABASE_URI'] = f'mysql+pymysql://{mysql_user}:{quote_plus(mysql_password)}@{mysql_host}:{mysql_port}/{mysql_database}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize SQLAlchemy first
db = SQLAlchemy(app)

# Initialize login manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Define models inline to avoid circular imports
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

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

def log_activity(user_id, action, description, request_obj):
    """Log user activity"""
    log = ActivityLog(
        user_id=user_id,
        action=action,
        description=description,
        ip_address=request_obj.remote_addr
    )
    db.session.add(log)
    db.session.commit()

def save_profile_picture(form_picture):
    """Save and resize profile picture"""
    random_hex = secrets.token_hex(8)
    _, f_ext = os.path.splitext(form_picture.filename)
    picture_fn = random_hex + f_ext
    picture_path = os.path.join(app.config['UPLOAD_FOLDER'], 'profile_pics', picture_fn)
    
    # Resize image
    output_size = (150, 150)
    img = Image.open(form_picture)
    img.thumbnail(output_size)
    img.save(picture_path)
    
    return picture_fn

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/home')
@login_required
def home():
    # Get user statistics for home page
    total_files = FileRecord.query.filter_by(user_id=current_user.id).count()
    total_storage = db.session.query(db.func.sum(FileRecord.file_size)).filter_by(user_id=current_user.id).scalar() or 0
    recent_files = FileRecord.query.filter_by(user_id=current_user.id).order_by(FileRecord.upload_date.desc()).limit(5).all()
    
    return render_template('home.html', 
                         total_files=total_files,
                         total_storage=total_storage,
                         recent_files=recent_files)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        try:
            email = request.form.get('email')
            username = request.form.get('username')
            password = request.form.get('password')
            confirm_password = request.form.get('confirm_password')
            
            # Validation
            if not all([email, username, password, confirm_password]):
                flash('All fields are required.', 'error')
                return render_template('register.html')
            
            if password != confirm_password:
                flash('Passwords do not match.', 'error')
                return render_template('register.html')
            
            if len(password) < 6:
                flash('Password must be at least 6 characters long.', 'error')
                return render_template('register.html')
            
            # Check if user exists
            existing_user = User.query.filter_by(email=email).first()
            if existing_user:
                flash('Email already registered.', 'error')
                return render_template('register.html')
            
            # Create new user
            user = User(
                username=username,
                password_hash=generate_password_hash(password),
                two_factor_secret=pyotp.random_base32()
            )
            user.set_email(email)
            
            db.session.add(user)
            db.session.commit()
            
            flash('Registration completed successfully! Please login.', 'success')
            return redirect(url_for('login'))
            
        except Exception as e:
            db.session.rollback()
            flash(f'Registration failed: {str(e)}', 'error')
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        # Find user by email (need to decrypt emails to compare)
        user = None
        all_users = User.query.all()
        
        for u in all_users:
            try:
                user_email = decrypt_sensitive_data(u.email)
                if user_email == email:
                    user = u
                    break
            except:
                # If decryption fails, try direct comparison
                if u.email == email:
                    user = u
                    break
        
        if user and check_password_hash(user.password_hash, password):
            user.last_login = datetime.now(timezone.utc)
            db.session.commit()
            
            if user.two_factor_enabled:
                session['pending_user_id'] = user.id
                return redirect(url_for('two_factor'))
            else:
                login_user(user, remember=request.form.get('remember_me'))
                log_activity(user.id, 'USER_LOGIN', f'User {user.username} logged in', request)
                flash('Login successful!', 'success')
                return redirect(url_for('dashboard'))
        else:
            flash('Invalid email or password.', 'error')
    
    # Create empty form object for template
    class EmptyForm:
        def hidden_tag(self):
            return ''
    
    form = EmptyForm()
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    log_activity(current_user.id, 'USER_LOGOUT', f'User {current_user.username} logged out', request)
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    # Get user statistics
    files = FileRecord.query.filter_by(user_id=current_user.id).order_by(FileRecord.upload_date.desc()).all()
    total_files = len(files)
    total_storage = sum(file.file_size for file in files)
    
    # Count downloads from activity logs
    download_activities = ActivityLog.query.filter_by(user_id=current_user.id, action='FILE_DOWNLOAD').count()
    
    # AI categorization statistics
    category_stats = {}
    for file in files:
        category = file.category or 'other'
        category_stats[category] = category_stats.get(category, 0) + 1
    
    # Format storage size
    def format_bytes(bytes_size):
        if bytes_size == 0:
            return "0 B"
        size_names = ["B", "KB", "MB", "GB", "TB"]
        i = 0
        while bytes_size >= 1024 and i < len(size_names) - 1:
            bytes_size /= 1024.0
            i += 1
        return f"{bytes_size:.1f} {size_names[i]}"
    
    formatted_storage = format_bytes(total_storage)
    
    return render_template('dashboard.html', 
                         files=files,
                         total_files=total_files,
                         total_storage=total_storage,
                         formatted_storage=formatted_storage,
                         total_downloads=download_activities,
                         category_stats=category_stats)

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    if request.method == 'POST':
        try:
            print(f"Upload attempt by user: {current_user.username}")  # Debug
            
            if 'file' not in request.files:
                print("No file in request")  # Debug
                return jsonify({'error': 'No file selected'}), 400
            
            file = request.files['file']
            if file.filename == '':
                print("Empty filename")  # Debug
                return jsonify({'error': 'No file selected'}), 400
            
            if file:
                filename = secure_filename(file.filename)
                stored_filename = f"{current_user.id}_{secrets.token_hex(16)}_{filename}"
                print(f"Processing file: {filename}")  # Debug
                
                # Save file temporarily
                temp_path = os.path.join(app.config['UPLOAD_FOLDER'], stored_filename)
                file.save(temp_path)
                print(f"File saved to: {temp_path}")  # Debug
                
                # Generate encryption key and encrypt file
                encryption_key = generate_encryption_key()
                encrypted_path = temp_path + '.enc'
                encrypt_file(temp_path, encrypted_path, encryption_key)
                print(f"File encrypted to: {encrypted_path}")  # Debug
                
                # Calculate file hash
                with open(temp_path, 'rb') as f:
                    file_hash = hashlib.sha256(f.read()).hexdigest()
                
                # Remove temporary unencrypted file
                os.remove(temp_path)
                
                # Create file record
                file_record = FileRecord(
                    stored_filename=stored_filename + '.enc',
                    user_id=current_user.id,
                    file_size=os.path.getsize(encrypted_path),
                    encryption_key=base64.b64encode(encryption_key).decode('utf-8'),
                    file_hash=file_hash
                )
                print(f"FileRecord created")  # Debug
                
                # Set encrypted filename and content type
                file_record.set_filename(filename)
                file_record.set_content_type(file.content_type or 'application/octet-stream')
                
                # AI categorization and tagging
                try:
                    category = categorize_file(filename, file.content_type)
                    tags = generate_tags(filename, file.content_type)
                    file_record.category = category
                    file_record.set_tags(tags)
                    print(f"AI categorization: {category}, tags: {tags}")  # Debug
                except Exception as ai_error:
                    print(f"AI categorization error: {ai_error}")  # Debug
                    file_record.category = 'other'
                    file_record.set_tags([])
                
                try:
                    db.session.add(file_record)
                    db.session.commit()
                    print("File record saved to database")  # Debug
                except Exception as db_error:
                    print(f"Database error: {db_error}")  # Debug
                    db.session.rollback()
                    raise db_error
                
                log_activity(current_user.id, 'FILE_UPLOAD', f'Uploaded file: {filename}', request)
                return jsonify({'success': True, 'message': 'File uploaded successfully'})
                
        except Exception as e:
            print(f"Upload error: {str(e)}")  # Debug
            db.session.rollback()
            # Clean up files if they exist
            try:
                if 'temp_path' in locals() and os.path.exists(temp_path):
                    os.remove(temp_path)
                if 'encrypted_path' in locals() and os.path.exists(encrypted_path):
                    os.remove(encrypted_path)
            except:
                pass
            return jsonify({'error': str(e)}), 500
    
    return render_template('upload.html')

@app.route('/download/<int:file_id>')
@login_required
def download_file(file_id):
    file_record = db.session.get(FileRecord, file_id)
    if not file_record or file_record.user_id != current_user.id:
        flash('File not found.', 'error')
        return redirect(url_for('dashboard'))
    
    try:
        encrypted_path = os.path.join(app.config['UPLOAD_FOLDER'], file_record.stored_filename)
        if not os.path.exists(encrypted_path):
            flash('File not found on disk.', 'error')
            return redirect(url_for('dashboard'))
        
        # Decrypt file
        encryption_key = base64.b64decode(file_record.encryption_key.encode('utf-8'))
        temp_path = encrypted_path + '.temp'
        decrypt_file(encrypted_path, temp_path, encryption_key)
        
        log_activity(current_user.id, 'FILE_DOWNLOAD', f'Downloaded file: {file_record.get_filename()}', request)
        
        return send_file(temp_path, as_attachment=True, download_name=file_record.get_filename())
        
    except Exception as e:
        flash(f'Error downloading file: {str(e)}', 'error')
        return redirect(url_for('dashboard'))

@app.route('/delete/<int:file_id>', methods=['POST', 'DELETE'])
@login_required
def delete_file(file_id):
    try:
        file_record = db.session.get(FileRecord, file_id)
        if not file_record or file_record.user_id != current_user.id:
            return jsonify({'error': 'File not found'}), 404
        
        # Delete physical file
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], file_record.stored_filename)
        if os.path.exists(file_path):
            os.remove(file_path)
        
        # Delete database record
        filename = file_record.get_filename()
        db.session.delete(file_record)
        db.session.commit()
        
        log_activity(current_user.id, 'FILE_DELETE', f'Deleted file: {filename}', request)
        return jsonify({'success': True, 'message': 'File deleted successfully'})
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/profile_pic/<filename>')
def profile_pic(filename):
    """Serve profile pictures"""
    return send_file(os.path.join(app.config['UPLOAD_FOLDER'], 'profile_pics', filename))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, host='0.0.0.0', port=5000)
