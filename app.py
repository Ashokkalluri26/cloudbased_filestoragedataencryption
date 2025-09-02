from flask import Flask, render_template, request, redirect, url_for, flash, send_file, jsonify, session
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
import os
import cx_Oracle
from datetime import datetime, timedelta
import secrets
import pyotp
import qrcode
from io import BytesIO
import base64

from models import db, User, FileRecord, ActivityLog, ShareLink
from encryption import encrypt_file, decrypt_file, generate_encryption_key
from forms import LoginForm, RegisterForm, UploadForm, TwoFactorForm

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['UPLOAD_FOLDER'] = os.getenv('UPLOAD_FOLDER', 'uploads')
app.config['MAX_CONTENT_LENGTH'] = int(os.getenv('MAX_CONTENT_LENGTH', 104857600))

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

oracle_user = os.getenv('ORACLE_USER')
oracle_password = os.getenv('ORACLE_PASSWORD')
oracle_dsn = os.getenv('ORACLE_DSN')

app.config['SQLALCHEMY_DATABASE_URI'] = f'oracle+cx_oracle://{oracle_user}:{oracle_password}@{oracle_dsn}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def log_activity(user_id, action, description):
    log = ActivityLog(user_id=user_id, action=action, description=description)
    db.session.add(log)
    db.session.commit()

@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        existing_user = User.query.filter_by(email=form.email.data).first()
        if existing_user:
            flash('Email already registered.', 'error')
            return render_template('register.html', form=form)
        
        user = User(
            username=form.username.data,
            email=form.email.data,
            password_hash=generate_password_hash(form.password.data),
            two_factor_secret=pyotp.random_base32()
        )
        
        db.session.add(user)
        db.session.commit()
        log_activity(user.id, 'USER_REGISTERED', f'User {user.username} registered')
        
        flash('Registration successful!', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        
        if user and check_password_hash(user.password_hash, form.password.data):
            if user.two_factor_enabled:
                session['pending_user_id'] = user.id
                return redirect(url_for('two_factor'))
            else:
                login_user(user, remember=form.remember_me.data)
                log_activity(user.id, 'USER_LOGIN', f'User {user.username} logged in')
                return redirect(url_for('dashboard'))
        else:
            flash('Invalid credentials.', 'error')
    
    return render_template('login.html', form=form)

@app.route('/two-factor', methods=['GET', 'POST'])
def two_factor():
    if 'pending_user_id' not in session:
        return redirect(url_for('login'))
    
    form = TwoFactorForm()
    if form.validate_on_submit():
        user = User.query.get(session['pending_user_id'])
        totp = pyotp.TOTP(user.two_factor_secret)
        
        if totp.verify(form.token.data):
            login_user(user)
            session.pop('pending_user_id', None)
            log_activity(user.id, 'USER_LOGIN', f'User {user.username} logged in with 2FA')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid 2FA token.', 'error')
    
    return render_template('two_factor.html', form=form)

@app.route('/logout')
@login_required
def logout():
    log_activity(current_user.id, 'USER_LOGOUT', f'User {current_user.username} logged out')
    logout_user()
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    files = FileRecord.query.filter_by(user_id=current_user.id).order_by(FileRecord.upload_date.desc()).all()
    return render_template('dashboard.html', files=files)

@app.route('/upload', methods=['POST'])
@login_required
def upload_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file selected'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    filename = secure_filename(file.filename)
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S_')
    unique_filename = timestamp + filename
    
    temp_path = os.path.join(app.config['UPLOAD_FOLDER'], 'temp_' + unique_filename)
    file.save(temp_path)
    
    encryption_key = generate_encryption_key()
    encrypted_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
    
    try:
        encrypt_file(temp_path, encrypted_path, encryption_key)
        os.remove(temp_path)
        
        file_record = FileRecord(
            filename=filename,
            stored_filename=unique_filename,
            user_id=current_user.id,
            file_size=os.path.getsize(encrypted_path),
            encryption_key=base64.b64encode(encryption_key).decode('utf-8')
        )
        
        db.session.add(file_record)
        db.session.commit()
        
        log_activity(current_user.id, 'FILE_UPLOAD', f'Uploaded file: {filename}')
        return jsonify({'success': True, 'message': 'File uploaded successfully'})
        
    except Exception as e:
        if os.path.exists(temp_path):
            os.remove(temp_path)
        return jsonify({'error': str(e)}), 500

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
        
        return send_file(temp_path, as_attachment=True, download_name=file_record.filename)
    except Exception as e:
        flash(f'Error downloading file: {str(e)}', 'error')
        return redirect(url_for('dashboard'))
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)

@app.route('/delete/<int:file_id>')
@login_required
def delete_file(file_id):
    file_record = FileRecord.query.filter_by(id=file_id, user_id=current_user.id).first()
    if not file_record:
        return jsonify({'error': 'File not found'}), 404
    
    encrypted_path = os.path.join(app.config['UPLOAD_FOLDER'], file_record.stored_filename)
    
    try:
        if os.path.exists(encrypted_path):
            os.remove(encrypted_path)
        
        db.session.delete(file_record)
        db.session.commit()
        
        log_activity(current_user.id, 'FILE_DELETE', f'Deleted file: {file_record.filename}')
        return jsonify({'success': True})
        
    except Exception as e:
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
        
        return send_file(temp_path, as_attachment=True, download_name=file_record.filename)
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)

@app.route('/setup-2fa')
@login_required
def setup_2fa():
    if current_user.two_factor_enabled:
        flash('2FA is already enabled.', 'info')
        return redirect(url_for('dashboard'))
    
    totp = pyotp.TOTP(current_user.two_factor_secret)
    qr_url = totp.provisioning_uri(
        current_user.email,
        issuer_name="Secure File Storage"
    )
    
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(qr_url)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    buffer = BytesIO()
    img.save(buffer, format='PNG')
    buffer.seek(0)
    
    qr_code_data = base64.b64encode(buffer.getvalue()).decode()
    
    return render_template('setup_2fa.html', qr_code=qr_code_data, secret=current_user.two_factor_secret)

@app.route('/enable-2fa', methods=['POST'])
@login_required
def enable_2fa():
    token = request.form.get('token')
    totp = pyotp.TOTP(current_user.two_factor_secret)
    
    if totp.verify(token):
        current_user.two_factor_enabled = True
        db.session.commit()
        flash('2FA enabled successfully!', 'success')
    else:
        flash('Invalid token. Please try again.', 'error')
    
    return redirect(url_for('dashboard'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
