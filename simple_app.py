from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os
import pyotp
import qrcode
from io import BytesIO
import base64

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///simple_new.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'uploads'

os.makedirs('uploads', exist_ok=True)

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    two_factor_secret = db.Column(db.String(32), nullable=True)

@app.route('/')
def index():
    return render_template('home.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    from forms import RegisterForm
    form = RegisterForm()
    
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email').strip()
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        # Debug all form data
        print(f"All form data: {dict(request.form)}")  # Debug
        
        # Strip whitespace from passwords
        if password:
            password = password.strip()
        if confirm_password:
            confirm_password = confirm_password.strip()
        
        # Basic validation
        if not username or not email or not password:
            flash('All fields are required.', 'error')
            return render_template('register.html')
        
        print(f"Password: '{password}' (len: {len(password) if password else 0})")  # Debug
        print(f"Confirm: '{confirm_password}' (len: {len(confirm_password) if confirm_password else 0})")  # Debug
        print(f"Match: {password == confirm_password}")  # Debug
        
        
        if len(password) < 6:
            flash('Password must be at least 6 characters long.', 'error')
            return render_template('register.html')
        
        print(f"Registration attempt - Username: {username}, Email: {email}")  # Debug
        
        # Check if user exists
        try:
            existing_user = User.query.filter_by(email=email).first()
            if existing_user:
                flash('Email already registered.', 'error')
                return render_template('register.html')
        except Exception as e:
            print(f"Error checking existing user: {str(e)}")
            flash('Database error. Please try again.', 'error')
            return render_template('register.html', form=form)
        
        # Create new user
        user = User(
            username=username,
            email=email,
            password_hash=generate_password_hash(password),
            two_factor_secret=pyotp.random_base32()
        )
        
        try:
            print(f"Attempting to save user: {username}")  # Debug
            db.session.add(user)
            print("User added to session")  # Debug
            db.session.commit()
            print(f"User {username} registered successfully")  # Debug
            flash('Registration completed successfully! Please login with your credentials.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            print(f"Registration error: {str(e)}")  # Debug
            print(f"Error type: {type(e)}")  # Debug
            flash(f'Registration failed: {str(e)}', 'error')
    
    return render_template('register.html')

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email').strip()
        password = request.form.get('password')
        
        print(f"Login attempt for email: '{email}'")  # Debug
        user = User.query.filter_by(email=email).first()
        print(f"User found: {user is not None}")  # Debug
        
        if user:
            print(f"Password check: {check_password_hash(user.password_hash, password)}")  # Debug
            if check_password_hash(user.password_hash, password):
                login_user(user)
                print(f"User logged in successfully")  # Debug
                
                # Create dashboard HTML directly
                dashboard_html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dashboard - SecureCloud</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <style>
        .feature-card {{ background: white; border-radius: 12px; padding: 24px; box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1); transition: transform 0.3s ease; height: 100%; border: 1px solid #e9ecef; }}
        .feature-card:hover {{ transform: translateY(-4px); }}
        .feature-icon {{ width: 60px; height: 60px; border-radius: 50%; display: flex; align-items: center; justify-content: center; margin-bottom: 16px; color: white; font-size: 24px; }}
    </style>
</head>
<body class="bg-light">
    <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
        <div class="container">
            <a class="navbar-brand" href="#"><i class="fas fa-shield-alt me-2"></i>SecureCloud</a>
            <div class="navbar-nav ms-auto">
                <div class="nav-item dropdown">
                    <a class="nav-link dropdown-toggle" href="#" role="button" data-bs-toggle="dropdown">
                        <i class="fas fa-user me-2"></i>{user.username}
                    </a>
                    <ul class="dropdown-menu">
                        <li><a class="dropdown-item" href="#"><i class="fas fa-user me-2"></i>Profile</a></li>
                        <li><a class="dropdown-item" href="#"><i class="fas fa-key me-2"></i>Change Password</a></li>
                        <li><a class="dropdown-item" href="#"><i class="fas fa-shield-alt me-2"></i>2FA Settings</a></li>
                        <li><hr class="dropdown-divider"></li>
                        <li><a class="dropdown-item" href="/logout"><i class="fas fa-sign-out-alt me-2"></i>Logout</a></li>
                    </ul>
                </div>
            </div>
        </div>
    </nav>
    
    <div class="container mt-4">
        <h1 class="mb-4">Dashboard</h1>
        <p class="lead">Welcome to your secure cloud storage platform!</p>
        
        <div class="row mb-4">
            <div class="col-md-6 col-lg-3 mb-3">
                <div class="feature-card">
                    <div class="feature-icon bg-primary"><i class="fas fa-cloud-upload-alt"></i></div>
                    <div class="feature-content">
                        <h5>File Upload & Download</h5>
                        <p>Securely upload and download files with AES-256 encryption</p>
                        <a href="#" class="btn btn-primary btn-sm">Access Feature</a>
                    </div>
                </div>
            </div>
            <div class="col-md-6 col-lg-3 mb-3">
                <div class="feature-card">
                    <div class="feature-icon bg-success"><i class="fas fa-user-cog"></i></div>
                    <div class="feature-content">
                        <h5>Profile Management</h5>
                        <p>Manage your account settings and personal information</p>
                        <a href="#" class="btn btn-success btn-sm">Access Feature</a>
                    </div>
                </div>
            </div>
            <div class="col-md-6 col-lg-3 mb-3">
                <div class="feature-card">
                    <div class="feature-icon bg-warning"><i class="fas fa-qrcode"></i></div>
                    <div class="feature-content">
                        <h5>2FA Setup with QR Code</h5>
                        <p>Enable two-factor authentication with Google Authenticator</p>
                        <a href="#" class="btn btn-warning btn-sm">Access Feature</a>
                    </div>
                </div>
            </div>
            <div class="col-md-6 col-lg-3 mb-3">
                <div class="feature-card">
                    <div class="feature-icon bg-info"><i class="fas fa-shield-alt"></i></div>
                    <div class="feature-content">
                        <h5>Secure File Storage</h5>
                        <p>Zero-knowledge encryption for maximum security</p>
                        <a href="#" class="btn btn-info btn-sm">Access Feature</a>
                    </div>
                </div>
            </div>
        </div>
    </div>
    
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
                """
                return dashboard_html
            else:
                flash('Invalid password.', 'error')
        else:
            flash('Email not found. Please register first.', 'error')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

@app.route('/profile')
@login_required
def profile():
    form = ProfileForm()
    return render_template('profile.html', form=form)

@app.route('/change_password')
@login_required
def change_password():
    form = ChangePasswordForm()
    return render_template('change_password.html', form=form)

@app.route('/setup_2fa')
@login_required
def setup_2fa():
    form = TwoFactorSetupForm()
    
    # Generate QR code for 2FA setup
    if current_user.two_factor_secret:
        # Create TOTP URI
        totp_uri = pyotp.totp.TOTP(current_user.two_factor_secret).provisioning_uri(
            name=current_user.email,
            issuer_name="SecureCloud"
        )
        
        # Generate QR code
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(totp_uri)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        buffered = BytesIO()
        img.save(buffered, format="PNG")
        img_str = base64.b64encode(buffered.getvalue()).decode()
        qr_code_url = f"data:image/png;base64,{img_str}"
        
        return render_template('setup_2fa.html', form=form, qr_code=qr_code_url, secret=current_user.two_factor_secret)
    
    return render_template('setup_2fa.html', form=form)

@app.route('/upload', methods=['POST'])
@login_required
def upload():
    try:
        if 'file' not in request.files:
            return jsonify({'success': False, 'error': 'No file selected'})
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'success': False, 'error': 'No file selected'})
        
        if file:
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            
            return jsonify({'success': True, 'message': 'File uploaded successfully'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/dashboard')
@login_required
def dashboard():
    print(f"Dashboard accessed by user: {current_user.username}")  # Debug
    
    # Dashboard with all features
    features = [
        {
            'title': 'File Upload & Download',
            'description': 'Securely upload and download files with AES-256 encryption',
            'icon': 'fas fa-cloud-upload-alt',
            'url': '#',
            'color': 'primary'
        },
        {
            'title': 'Profile Management',
            'description': 'Manage your account settings and personal information',
            'icon': 'fas fa-user-cog',
            'url': '#',
            'color': 'success'
        },
        {
            'title': '2FA Setup with QR Code',
            'description': 'Enable two-factor authentication with Google Authenticator',
            'icon': 'fas fa-qrcode',
            'url': '#',
            'color': 'warning'
        },
        {
            'title': 'Secure File Storage',
            'description': 'Zero-knowledge encryption for maximum security',
            'icon': 'fas fa-shield-alt',
            'url': '#',
            'color': 'info'
        }
    ]
    
    print(f"Rendering dashboard with {len(features)} features")  # Debug
    return render_template('dashboard_simple.html', 
                         file_count=0,
                         storage_used='0 MB', 
                         shared_files=0,
                         downloads=0,
                         files=[],
                         features=features)

if __name__ == '__main__':
    with app.app_context():
        try:
            db.create_all()
            print("Database tables created successfully")
            
            # Test database connection
            from sqlalchemy import text
            result = db.session.execute(text("SELECT 1"))
            print("Database connection test: OK")
            
        except Exception as e:
            print(f"Database setup error: {e}")
    
    app.run(debug=True)
