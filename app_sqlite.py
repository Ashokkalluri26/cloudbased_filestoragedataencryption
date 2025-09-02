from flask import Flask, render_template, request, redirect, url_for, flash, send_file, jsonify, session
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from PIL import Image
from dotenv import load_dotenv
import os
import sqlite3
import time
from datetime import datetime, timezone, timedelta
import secrets
import pyotp
import qrcode
from io import BytesIO
import base64

from models_sqlite import db, User, FileRecord, ActivityLog, ShareLink
from forms import LoginForm, RegisterForm
from security_utils import hash_password_secure, verify_password_secure, log_activity
from encryption import encrypt_file, decrypt_file, generate_file_key, encrypt_sensitive_data

# Alias for compatibility
generate_encryption_key = generate_file_key
from ai_categorizer import categorize_file, generate_tags
from subscription import subscription_bp
from forms import LoginForm, RegisterForm, UploadForm, TwoFactorForm, ProfileForm, ChangePasswordForm, TwoFactorSetupForm
from ai_categorizer import categorize_file, generate_tags, get_file_insights

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production')
app.config['UPLOAD_FOLDER'] = os.getenv('UPLOAD_FOLDER', 'uploads')
app.config['MAX_CONTENT_LENGTH'] = int(os.getenv('MAX_CONTENT_LENGTH', 104857600))

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(os.path.join(app.config['UPLOAD_FOLDER'], 'profile_pics'), exist_ok=True)

# Database Configuration - Use SQLite with Oracle schema compatibility
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///secure_storage.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {}

# Oracle connection will be configured when Oracle DB is available
# For now, using SQLite with models.py (Oracle-compatible schema)

db.init_app(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'
login_manager.login_message_category = 'info'

# Register blueprints
app.register_blueprint(subscription_bp)

@login_manager.user_loader
def load_user(user_id):
    try:
        user = db.session.get(User, int(user_id))
        print(f"Loading user: {user.username if user else 'None'} (ID: {user_id})")  # Debug
        return user
    except Exception as e:
        print(f"Error loading user {user_id}: {e}")  # Debug
        return None

def log_activity(user_id, action, description, request=None):
    log = ActivityLog(user_id=user_id, action=action)
    log.set_description(description)
    
    if request:
        log.set_ip_address(request.remote_addr or 'unknown')
        log.user_agent = encrypt_sensitive_data(request.headers.get('User-Agent', 'unknown'))
    
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
    
    # Get recent activities
    recent_activities = ActivityLog.query.filter_by(user_id=current_user.id).order_by(ActivityLog.timestamp.desc()).limit(10).all()
    
    # Get file categories for AI insights
    files = FileRecord.query.filter_by(user_id=current_user.id).all()
    category_stats = {}
    for file in files:
        category = file.category or 'other'
        category_stats[category] = category_stats.get(category, 0) + 1
    
    # Format storage size
    def format_file_size(size_bytes):
        if size_bytes == 0:
            return "0 B"
        size_names = ["B", "KB", "MB", "GB", "TB"]
        import math
        i = int(math.floor(math.log(size_bytes, 1024)))
        p = math.pow(1024, i)
        s = round(size_bytes / p, 2)
        return f"{s} {size_names[i]}"
    
    formatted_storage = format_file_size(total_storage)
    
    # Get download count
    download_count = ActivityLog.query.filter_by(user_id=current_user.id, action='FILE_DOWNLOAD').count()
    
    # Get shared files count
    shared_files = ShareLink.query.join(FileRecord).filter(FileRecord.user_id == current_user.id).count()
    
    return render_template('user_home.html', 
                         total_files=total_files,
                         total_storage=total_storage,
                         formatted_storage=formatted_storage,
                         recent_files=recent_files,
                         recent_activities=recent_activities,
                         category_stats=category_stats,
                         download_count=download_count,
                         shared_files=shared_files)

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if request.method == 'POST':
        try:
            email = request.form.get('email')
            username = request.form.get('username')
            password = request.form.get('password')
            password2 = request.form.get('password2')
            
            # Basic validation
            if not username or not email or not password:
                flash('All fields are required.', 'error')
                return render_template('register.html', form=form)
                
            if len(password) < 6:
                flash('Password must be at least 6 characters long.', 'error')
                return render_template('register.html', form=form)
            
            print(f"Password: '{password}', Password2: '{password2}'")  # Debug
            # Skip password confirmation for now
            # if password != password2:
            #     flash('Passwords do not match.', 'error')
            #     return render_template('register.html', form=form)
            
            # Check if user already exists
            existing_users = User.query.all()
            for existing_user in existing_users:
                if existing_user.get_email() == email:
                    flash('Email already registered.', 'error')
                    return render_template('register.html', form=form)
            
            user = User(
                username=username,
                two_factor_secret=pyotp.random_base32()
            )
            user.set_email(email)
            user.password_hash = hash_password_secure(password)
            
            db.session.add(user)
            db.session.commit()
            
            # Create user directory after getting user ID
            user_dir = os.path.join(app.config['UPLOAD_FOLDER'], str(user.id))
            os.makedirs(user_dir, exist_ok=True)
            
            log_activity(user.id, 'USER_REGISTERED', f'User {user.username} registered', request)
            
            flash('Registration successful! You can now login.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            print(f"Registration error: {e}")
            import traceback
            traceback.print_exc()
            flash(f'Registration failed: {str(e)}', 'error')
    
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        print(f"Login attempt - Email: '{email}', Password: '{password}'")  # Debug
        
        # Find user by email (need to decrypt emails to compare)
        user = None
        all_users = User.query.all()
        
        for u in all_users:
            try:
                user_email = u.get_email()
                if user_email and user_email.lower() == email.lower():
                    user = u
                    break
            except Exception as e:
                print(f"Error decrypting email for user {u.username}: {e}")
                continue
        
        if user:
            print(f"User found: {user.username}")  # Debug
            password_valid = verify_password_secure(password, user.password_hash)
            print(f"Password valid: {password_valid}")  # Debug
            
            if password_valid:
                # Update last login time
                user.last_login = datetime.now(timezone.utc)
                db.session.commit()
                
                if user.two_factor_enabled:
                    session['pending_user_id'] = user.id
                    return redirect(url_for('two_factor'))
                else:
                    login_user(user, remember=request.form.get('remember_me'))
                    log_activity(user.id, 'USER_LOGIN', f'User {user.username} logged in', request)
                    print(f"User logged in successfully")  # Debug
                    return redirect(url_for('dashboard'))
            else:
                flash('Invalid password.', 'error')
        else:
            flash('Email not found. Please register first.', 'error')
    
    form = LoginForm()
    return render_template('login.html', form=form)

@app.route('/two-factor', methods=['GET', 'POST'])
def two_factor():
    if 'pending_user_id' not in session:
        return redirect(url_for('login'))
    
    form = TwoFactorForm()
    if form.validate_on_submit():
        user = db.session.get(User, session['pending_user_id'])
        totp = pyotp.TOTP(user.get_two_factor_secret())
        
        if totp.verify(form.token.data):
            login_user(user)
            session.pop('pending_user_id', None)
            log_activity(user.id, 'USER_LOGIN', f'User {user.username} logged in with 2FA', request)
            # Return dashboard HTML directly instead of redirect
            dashboard_html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Dashboard - SecureCloud</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
</head>
<body class="bg-light">
    <nav class="navbar navbar-dark bg-dark">
        <div class="container">
            <a class="navbar-brand" href="#"><i class="fas fa-shield-alt me-2"></i>SecureCloud</a>
            <div class="navbar-nav ms-auto">
                <a class="nav-link" href="/logout">Logout</a>
            </div>
        </div>
    </nav>
    
    <div class="container mt-4">
        <div class="alert alert-success">
            <i class="fas fa-check-circle me-2"></i>Successfully logged in with 2FA!
        </div>
        <h1>Welcome to your Dashboard</h1>
        <p>Your account is protected with two-factor authentication.</p>
        
        <div class="row">
            <div class="col-md-3">
                <div class="card">
                    <div class="card-body text-center">
                        <i class="fas fa-upload text-primary" style="font-size: 2rem;"></i>
                        <h5 class="mt-2">File Upload</h5>
                        <a href="/upload" class="btn btn-primary">Upload Files</a>
                    </div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card">
                    <div class="card-body text-center">
                        <i class="fas fa-user text-success" style="font-size: 2rem;"></i>
                        <h5 class="mt-2">Profile</h5>
                        <a href="/profile" class="btn btn-success">View Profile</a>
                    </div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card">
                    <div class="card-body text-center">
                        <i class="fas fa-shield-alt text-warning" style="font-size: 2rem;"></i>
                        <h5 class="mt-2">2FA Settings</h5>
                        <a href="/profile/setup-2fa" class="btn btn-warning">Manage 2FA</a>
                    </div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card">
                    <div class="card-body text-center">
                        <i class="fas fa-files text-info" style="font-size: 2rem;"></i>
                        <h5 class="mt-2">Files</h5>
                        <a href="/home" class="btn btn-info">View Files</a>
                    </div>
                </div>
            </div>
        </div>
    </div>
</body>
</html>
            """
            return dashboard_html
        else:
            flash('Invalid 2FA token.', 'error')
            log_activity(user.id, '2FA_FAILED', f'Invalid 2FA token for {user.username}', request)
    
    return render_template('two_factor.html', form=form)

@app.route('/logout')
@login_required
def logout():
    log_activity(current_user.id, 'USER_LOGOUT', f'User {current_user.username} logged out', request)
    logout_user()
    return redirect(url_for('index'))

@app.route('/profile')
@login_required
def profile():
    print(f"Profile accessed by user: {current_user.username} (ID: {current_user.id})")  # Debug
    # Get user statistics
    total_files = FileRecord.query.filter_by(user_id=current_user.id).count()
    total_storage = db.session.query(db.func.sum(FileRecord.file_size)).filter_by(user_id=current_user.id).scalar() or 0
    recent_activities = ActivityLog.query.filter_by(user_id=current_user.id).order_by(ActivityLog.timestamp.desc()).limit(10).all()
    
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
    
    # AI categorization statistics for profile
    category_stats = {}
    files = FileRecord.query.filter_by(user_id=current_user.id).all()
    for file in files:
        category = file.category or 'other'
        category_stats[category] = category_stats.get(category, 0) + 1
    
    return render_template('profile.html', 
                         total_files=total_files,
                         total_storage=total_storage,
                         formatted_storage=formatted_storage,
                         recent_activities=recent_activities,
                         category_stats=category_stats)

@app.route('/profile/edit', methods=['GET', 'POST'])
@login_required
def edit_profile():
    print(f"Profile edit accessed by user: {current_user.username}")  # Debug
    
    if request.method == 'POST':
        print("Profile edit POST request received")  # Debug
        
        # Get form data directly
        username = request.form.get('username')
        email = request.form.get('email')
        bio = request.form.get('bio')
        
        print(f"Form data - Username: {username}, Email: {email}, Bio: {bio}")  # Debug
        
        try:
            # Handle profile picture upload first (independent of other validations)
            if 'profile_picture' in request.files:
                file = request.files['profile_picture']
                if file and file.filename:
                    print(f"Profile picture uploaded: {file.filename}")  # Debug
                    # Delete old profile picture if exists
                    if current_user.profile_picture:
                        old_pic_path = os.path.join(app.config['UPLOAD_FOLDER'], 'profile_pics', current_user.profile_picture)
                        if os.path.exists(old_pic_path):
                            os.remove(old_pic_path)
                    
                    # Save new profile picture
                    picture_file = save_profile_picture(file)
                    current_user.profile_picture = picture_file
                    
                    # If only uploading picture, commit and redirect
                    if not username and not email and not bio:
                        db.session.commit()
                        log_activity(current_user.id, 'PROFILE_UPDATE', 'Profile picture updated', request)
                        flash('Profile picture updated successfully!', 'success')
                        return redirect(url_for('profile'))
                    
                    # If uploading picture with other data, continue to validation
                    db.session.commit()
                    flash('Profile picture updated successfully!', 'success')
            
            # Basic validation for other fields
            if username or email or bio:
                if not username or not email:
                    flash('Username and email are required.', 'error')
                    return render_template('edit_profile.html', 
                                         username=current_user.username,
                                         email=current_user.get_email(),
                                         bio=current_user.get_bio())
                
                # Check if username is already taken (excluding current user)
                if username != current_user.username:
                    existing_user = User.query.filter(User.username == username, User.id != current_user.id).first()
                    if existing_user:
                        flash('Username already taken.', 'error')
                        return render_template('edit_profile.html', 
                                             username=current_user.username,
                                             email=current_user.get_email(),
                                             bio=current_user.get_bio())
                
                # Check if email is already taken (only if email is being changed)
                if email != current_user.get_email():
                    all_users = User.query.filter(User.id != current_user.id).all()
                    for user in all_users:
                        if user.get_email() == email:
                            flash('Email already registered.', 'error')
                            return render_template('edit_profile.html', 
                                                 username=current_user.username,
                                                 email=current_user.get_email(),
                                                 bio=current_user.get_bio())
                
                # Update user profile
                current_user.username = username
                current_user.set_email(email)
                current_user.set_bio(bio)
            
            db.session.commit()
            print(f"Profile updated successfully for user: {username}")  # Debug
            log_activity(current_user.id, 'PROFILE_UPDATE', 'Profile information updated', request)
            flash('Profile updated successfully!', 'success')
            return redirect(url_for('profile'))
            
        except Exception as e:
            print(f"Error updating profile: {str(e)}")  # Debug
            db.session.rollback()
            flash(f'Error updating profile: {str(e)}', 'error')
    
    # GET request - show form with current data
    return render_template('edit_profile.html', 
                         username=current_user.username,
                         email=current_user.get_email(),
                         bio=current_user.get_bio())

@app.route('/profile_pic/<filename>')
def profile_pic(filename):
    """Serve profile pictures"""
    return send_file(os.path.join(app.config['UPLOAD_FOLDER'], 'profile_pics', filename))

@app.route('/profile/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    form = ChangePasswordForm()
    
    if form.validate_on_submit():
        if not verify_password_secure(form.current_password.data, current_user.password_hash):
            flash('Current password is incorrect.', 'error')
            return render_template('change_password.html', form=form)
        
        current_user.password_hash = hash_password_secure(form.new_password.data)
        db.session.commit()
        log_activity(current_user.id, 'PASSWORD_CHANGE', 'Password changed successfully', request)
        flash('Password changed successfully!', 'success')
        return redirect(url_for('profile'))
    
    return render_template('change_password.html', form=form)

@app.route('/profile/setup-2fa', methods=['GET', 'POST'])
@login_required
def setup_2fa():
    if current_user.two_factor_enabled:
        flash('Two-factor authentication is already enabled.', 'info')
        return redirect(url_for('profile'))
    
    # Get or generate secret
    secret = session.get('temp_2fa_secret')
    if not secret:
        secret = pyotp.random_base32()
        session['temp_2fa_secret'] = secret
    
    print(f"Using secret: {secret}")  # Debug
    
    totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
        name=current_user.get_email(),
        issuer_name="SecureCloud"
    )
    
    print(f"TOTP URI: {totp_uri}")  # Debug
    
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=8,
        border=4,
    )
    qr.add_data(totp_uri)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    buffered = BytesIO()
    img.save(buffered, format='PNG')
    img_str = base64.b64encode(buffered.getvalue()).decode()
    
    if request.method == 'POST':
        token = request.form.get('token')
        print(f"Received token: {token}")  # Debug
        
        if not token:
            print("No token provided")  # Debug
            return render_template('setup_2fa.html', qr_code=img_str, secret=secret, error="Please enter a token")
        
        if len(token) != 6 or not token.isdigit():
            print(f"Invalid token format: {token}")  # Debug
            return render_template('setup_2fa.html', qr_code=img_str, secret=secret, error="Please enter a valid 6-digit code")
        
        totp = pyotp.TOTP(secret)
        print(f"Expected token: {totp.now()}")  # Debug
        print(f"Received token: {token}")  # Debug
        
        # Simple token verification without time windows
        valid = totp.verify(token)
        print(f"Token valid: {valid}")  # Debug
        
        if valid:
            try:
                current_user.set_two_factor_secret(secret)
                current_user.two_factor_enabled = True
                db.session.commit()
                session.pop('temp_2fa_secret', None)
                log_activity(current_user.id, '2FA_ENABLED', 'Two-factor authentication enabled', request)
                print(f"2FA enabled for user {current_user.username}")  # Debug
                
                # Show success message on the same page instead of redirecting
                return render_template('setup_2fa.html', 
                                     qr_code=img_str, 
                                     secret=secret, 
                                     success=True,
                                     success_message="Two-factor authentication enabled successfully! Your account is now protected.")
            except Exception as e:
                print(f"Error enabling 2FA: {e}")
                return render_template('setup_2fa.html', qr_code=img_str, secret=secret, error="Error enabling 2FA. Please try again.")
        else:
            print("Token verification failed")  # Debug
            return render_template('setup_2fa.html', qr_code=img_str, secret=secret, error="Invalid token. Please try again.")
    
    return render_template('setup_2fa.html', qr_code=img_str, secret=secret)

@app.route('/profile/disable-2fa', methods=['POST'])
@login_required
def disable_2fa():
    if not current_user.two_factor_enabled:
        flash('Two-factor authentication is not enabled.', 'info')
        return redirect(url_for('profile'))
    
    current_user.two_factor_enabled = False
    current_user.two_factor_secret = None
    db.session.commit()
    log_activity(current_user.id, '2FA_DISABLED', 'Two-factor authentication disabled', request)
    flash('Two-factor authentication disabled.', 'success')
    return redirect(url_for('profile'))

@app.route('/dashboard')
@login_required
def dashboard():
    print(f"Dashboard accessed by user: {current_user.username} (ID: {current_user.id})")  # Debug
    
    # Get user statistics
    files = FileRecord.query.filter_by(user_id=current_user.id).order_by(FileRecord.upload_date.desc()).all()
    total_files = len(files)
    total_storage = sum(file.file_size for file in files)
    
    # Count downloads from activity logs
    download_activities = ActivityLog.query.filter_by(user_id=current_user.id, action='FILE_DOWNLOAD').count()
    
    # Count shared files
    shared_files = ShareLink.query.join(FileRecord).filter(FileRecord.user_id == current_user.id).count()
    
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
    
    # Dashboard features
    features = [
        {
            'title': 'File Upload & Download',
            'description': 'Securely upload and download files with AES-256 encryption',
            'icon': 'fas fa-cloud-upload-alt',
            'color': 'primary',
            'url': '/upload'
        },
        {
            'title': 'Profile Management',
            'description': 'Manage your account settings and personal information',
            'icon': 'fas fa-user-cog',
            'color': 'success',
            'url': '/profile'
        },
        {
            'title': '2FA Security',
            'description': 'Enable two-factor authentication with Google Authenticator',
            'icon': 'fas fa-shield-alt',
            'color': 'warning',
            'url': '/profile/setup-2fa'
        },
        {
            'title': 'AI File Insights',
            'description': 'AI-powered file categorization and smart tagging',
            'icon': 'fas fa-brain',
            'color': 'info',
            'url': '/profile#ai-section'
        }
    ]
    
    return render_template('dashboard.html', 
                         files=files,
                         total_files=total_files,
                         total_storage=total_storage,
                         formatted_storage=formatted_storage,
                         total_downloads=download_activities,
                         shared_files=shared_files,
                         category_stats=category_stats,
                         features=features)

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    # Check if user can upload more files
    if not current_user.can_upload_files():
        remaining = current_user.get_remaining_files()
        if remaining == 0:
            flash('You have reached your file upload limit (50 files). Upgrade to premium for unlimited uploads!', 'error')
            return redirect(url_for('subscription'))
    
    if request.method == 'GET':
        remaining_files = current_user.get_remaining_files()
        subscription_info = {
            'type': current_user.subscription_type,
            'remaining': remaining_files if remaining_files != float('inf') else 'Unlimited'
        }
        # Return upload page
        return f"""
<!DOCTYPE html>
<html>
<head>
    <title>Upload File - SecureCloud</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
</head>
<body class="bg-light">
    <nav class="navbar navbar-dark bg-dark">
        <div class="container">
            <a class="navbar-brand" href="/home"><i class="fas fa-shield-alt me-2"></i>SecureCloud</a>
            <div class="navbar-nav ms-auto">
                <a class="nav-link" href="/home">Dashboard</a>
                <a class="nav-link" href="/logout">Logout</a>
            </div>
        </div>
    </nav>
    
    <div class="container mt-4">
        <div class="row justify-content-center">
            <div class="col-md-8">
                <div class="card">
                    <div class="card-header">
                        <h3><i class="fas fa-cloud-upload-alt me-2"></i>Upload File</h3>
                    </div>
                    <div class="card-body">
                        <div class="alert alert-info mb-3">
                            <i class="fas fa-info-circle me-2"></i>
                            <strong>Subscription:</strong> {subscription_info['type'].title()} | 
                            <strong>Remaining uploads:</strong> {subscription_info['remaining']}
                        </div>
                        <form method="POST" enctype="multipart/form-data">
                            <div class="mb-3">
                                <label for="file" class="form-label">Select File</label>
                                <input type="file" class="form-control" name="file" id="file" required>
                                <div class="form-text">Files will be encrypted with AES-256 encryption</div>
                            </div>
                            <button type="submit" class="btn btn-primary">
                                <i class="fas fa-upload me-2"></i>Upload File
                            </button>
                            <a href="/home" class="btn btn-secondary ms-2">Cancel</a>
                        </form>
                    </div>
                </div>
            </div>
        </div>
    </div>
</body>
</html>
        """
    
    # Handle POST request
    try:
        file = request.files.get('file')
        print(f"Upload attempt - File: {file}")  # Debug
        
        if not file or not file.filename:
            return f"""
<!DOCTYPE html>
<html>
<head>
    <title>Upload Failed - SecureCloud</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body class="bg-light">
    <div class="container mt-5">
        <div class="alert alert-danger">
            <h4>Upload Failed</h4>
            <p>No file selected. Please go back and select a file.</p>
            <a href="/upload" class="btn btn-primary">Try Again</a>
        </div>
    </div>
</body>
</html>
            """
        
        filename = secure_filename(file.filename)
        stored_filename = f"{secrets.token_hex(16)}_{filename}"
        
        # Ensure upload folder exists
        os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], stored_filename)
        
        print(f"Saving file to: {file_path}")  # Debug
        file.save(file_path)
        
        # Generate file hash before encryption
        import hashlib
        with open(file_path, 'rb') as f:
            file_hash = hashlib.sha256(f.read()).hexdigest()
        
        encryption_key = generate_encryption_key()
        encrypted_path = file_path + '.enc'
        
        encrypt_file(file_path, encrypted_path, encryption_key)
        os.remove(file_path)
        
        file_record = FileRecord(
            stored_filename=stored_filename + '.enc',
            user_id=current_user.id,
            file_size=os.path.getsize(encrypted_path),
            encryption_key=base64.b64encode(encryption_key).decode('utf-8'),
            file_hash=file_hash
        )
        
        # Set encrypted filename and content type
        file_record.set_filename(filename)
        file_record.set_content_type(file.content_type or 'application/octet-stream')
        
        # AI categorization and tagging
        try:
            category = categorize_file(filename, file.content_type)
            tags = generate_tags(filename, file.content_type)
            file_record.category = category
            file_record.set_tags(tags)
            print(f"AI categorization - Category: {category}, Tags: {tags}")  # Debug
        except Exception as ai_error:
            print(f"AI categorization error: {ai_error}")  # Debug
            file_record.category = 'other'
            file_record.set_tags([])
        
        try:
            db.session.add(file_record)
            db.session.commit()
            current_user.increment_file_count()
            print(f"File record saved successfully for {filename}")  # Debug
        except Exception as db_error:
            print(f"Database error: {db_error}")  # Debug
            db.session.rollback()
            raise db_error
        
        log_activity(current_user.id, 'FILE_UPLOAD', f'Uploaded file: {filename}', request)
        
        # Return JSON response for AJAX upload
        return jsonify({
            'success': True,
            'message': 'File uploaded successfully!',
            'file_id': file_record.id,
            'filename': filename,
            'category': file_record.category
        })
        
    except Exception as e:
        print(f"Upload error: {str(e)}")  # Debug
        # Clean up any partial files
        try:
            if 'file_path' in locals() and os.path.exists(file_path):
                os.remove(file_path)
            if 'encrypted_path' in locals() and os.path.exists(encrypted_path):
                os.remove(encrypted_path)
        except:
            pass
        
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/download/<int:file_id>')
@login_required
def download_file(file_id):
    file_record = FileRecord.query.filter_by(id=file_id, user_id=current_user.id).first()
    if not file_record:
        flash('File not found.', 'error')
        return redirect(url_for('dashboard'))
    
    encrypted_path = os.path.join(app.config['UPLOAD_FOLDER'], file_record.stored_filename)
    temp_path = os.path.join(app.config['UPLOAD_FOLDER'], 'temp_download_' + file_record.stored_filename)
    
    try:
        encryption_key = base64.b64decode(file_record.encryption_key.encode('utf-8'))
        decrypt_file(encrypted_path, temp_path, encryption_key)
        
        log_activity(current_user.id, 'FILE_DOWNLOAD', f'Downloaded file: {file_record.filename}')
        
        # Read file content into memory and delete temp file immediately
        with open(temp_path, 'rb') as f:
            file_data = f.read()
        
        # Clean up temp file
        try:
            os.remove(temp_path)
        except:
            pass  # Ignore cleanup errors
        
        # Return file from memory
        from flask import Response
        return Response(
            file_data,
            headers={
                'Content-Disposition': f'attachment; filename="{file_record.filename}"',
                'Content-Type': 'application/octet-stream'
            }
        )
        
    except Exception as e:
        # Clean up temp file on error
        try:
            if os.path.exists(temp_path):
                os.remove(temp_path)
        except:
            pass
        flash(f'Error downloading file: {str(e)}', 'error')
        return redirect(url_for('dashboard'))

@app.route('/delete/<int:file_id>', methods=['POST', 'DELETE'])
@login_required
def delete_file(file_id):
    print(f"Delete request for file ID: {file_id} by user: {current_user.username}")  # Debug
    
    file_record = FileRecord.query.filter_by(id=file_id, user_id=current_user.id).first()
    if not file_record:
        print(f"File not found: {file_id}")  # Debug
        return jsonify({'error': 'File not found'}), 404
    
    encrypted_path = os.path.join(app.config['UPLOAD_FOLDER'], file_record.stored_filename)
    print(f"Attempting to delete file: {encrypted_path}")  # Debug
    
    try:
        # Get filename before deletion for logging
        original_filename = file_record.get_filename()
        
        # Delete physical file
        if os.path.exists(encrypted_path):
            os.remove(encrypted_path)
            print(f"Physical file deleted: {encrypted_path}")  # Debug
        else:
            print(f"Physical file not found: {encrypted_path}")  # Debug
        
        # Delete database record
        db.session.delete(file_record)
        db.session.commit()
        print(f"Database record deleted for file: {original_filename}")  # Debug
        
        log_activity(current_user.id, 'FILE_DELETE', f'Deleted file: {original_filename}', request)
        return jsonify({'success': True, 'message': 'File deleted successfully'})
        
    except Exception as e:
        print(f"Error deleting file: {str(e)}")  # Debug
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/share/<int:file_id>')
@login_required
def create_share_link(file_id):
    file_record = FileRecord.query.filter_by(id=file_id, user_id=current_user.id).first()
    if not file_record:
        return jsonify({'error': 'File not found'}), 404
    
    token = secrets.token_urlsafe(32)
    expires_at = datetime.now() + timedelta(hours=24)
    
    share_link = ShareLink(
        token=token,
        file_id=file_id,
        created_by=current_user.id,
        expires_at=expires_at
    )
    
    db.session.add(share_link)
    db.session.commit()
    
    share_url = url_for('shared_download', token=token, _external=True)
    return jsonify({'share_url': share_url, 'expires_at': expires_at.isoformat()})

@app.route('/shared/<token>')
def shared_download(token):
    share_link = ShareLink.query.filter_by(token=token).first()
    if not share_link or share_link.expires_at < datetime.now():
        flash('Share link expired or invalid.', 'error')
        return redirect(url_for('index'))
    
    file_record = FileRecord.query.get(share_link.file_id)
    encrypted_path = os.path.join(app.config['UPLOAD_FOLDER'], file_record.stored_filename)
    temp_path = os.path.join(app.config['UPLOAD_FOLDER'], 'temp_shared_' + file_record.stored_filename)
    
    try:
        encryption_key = base64.b64decode(file_record.encryption_key.encode('utf-8'))
        decrypt_file(encrypted_path, temp_path, encryption_key)
        
        # Read file content into memory and delete temp file immediately
        with open(temp_path, 'rb') as f:
            file_data = f.read()
        
        # Clean up temp file
        try:
            os.remove(temp_path)
        except:
            pass  # Ignore cleanup errors
        
        # Return file from memory
        from flask import Response
        return Response(
            file_data,
            headers={
                'Content-Disposition': f'attachment; filename="{file_record.filename}"',
                'Content-Type': 'application/octet-stream'
            }
        )
        
    except Exception as e:
        # Clean up temp file on error
        try:
            if os.path.exists(temp_path):
                os.remove(temp_path)
        except:
            pass
        flash(f'Error downloading shared file: {str(e)}', 'error')
        return redirect(url_for('index'))


if __name__ == '__main__':
    with app.app_context():
        try:
            db.create_all()
            print("Database tables created successfully!")
            
            # Check if database is working
            from models_sqlite import User
            test_count = User.query.count()
            print(f"Current users in database: {test_count}")
            
        except Exception as e:
            print(f"Database initialization error: {e}")
            # Try to recreate database
            try:
                db.drop_all()
                db.create_all()
                print("Database recreated successfully!")
            except Exception as e2:
                print(f"Failed to recreate database: {e2}")
    
    app.run(debug=True, host='0.0.0.0', port=5000)
