from flask import Flask, render_template, request, redirect, url_for, flash, send_file, jsonify, session
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask_cors import CORS
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
import json
import hashlib
import magic
import redis
from celery import Celery
import requests
from webauthn import generate_registration_options, verify_registration_response, generate_authentication_options, verify_authentication_response
from webauthn.helpers.structs import RegistrationCredential, AuthenticationCredential
from webauthn.helpers.cose import COSEAlgorithmIdentifier

from models import (db, User, FileRecord, ActivityLog, ShareLink, WebAuthnCredential, 
                   FileChunk, SyncSession, SecurityEvent)
from encryption import encrypt_file, decrypt_file, generate_encryption_key
from forms import LoginForm, RegisterForm, UploadForm, TwoFactorForm
from ai_categorizer import categorize_file, generate_tags
from security_utils import detect_suspicious_activity, log_security_event

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['UPLOAD_FOLDER'] = os.getenv('UPLOAD_FOLDER', 'uploads')
app.config['MAX_CONTENT_LENGTH'] = int(os.getenv('MAX_CONTENT_LENGTH', 104857600))

# Enhanced configuration
app.config['REDIS_URL'] = os.getenv('REDIS_URL', 'redis://localhost:6379/0')
app.config['CELERY_BROKER_URL'] = os.getenv('REDIS_URL', 'redis://localhost:6379/0')
app.config['WEBAUTHN_RP_ID'] = os.getenv('WEBAUTHN_RP_ID', 'localhost')
app.config['WEBAUTHN_RP_NAME'] = os.getenv('WEBAUTHN_RP_NAME', 'SecureCloud Storage')
app.config['WEBAUTHN_ORIGIN'] = os.getenv('WEBAUTHN_ORIGIN', 'http://localhost:5000')

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Database configuration
oracle_user = os.getenv('ORACLE_USER')
oracle_password = os.getenv('ORACLE_PASSWORD')
oracle_dsn = os.getenv('ORACLE_DSN')

app.config['SQLALCHEMY_DATABASE_URI'] = f'oracle+cx_oracle://{oracle_user}:{oracle_password}@{oracle_dsn}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize extensions
db.init_app(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
socketio = SocketIO(app, cors_allowed_origins="*")
CORS(app)

# Redis connection
redis_client = redis.from_url(app.config['REDIS_URL'])

# Celery configuration
celery = Celery(app.name, broker=app.config['CELERY_BROKER_URL'])
celery.conf.update(app.config)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def log_activity(user_id, action, description, ip_address=None, user_agent=None, risk_level='low'):
    """Enhanced activity logging with security context"""
    log = ActivityLog(
        user_id=user_id, 
        action=action, 
        description=description,
        ip_address=ip_address or request.remote_addr,
        user_agent=user_agent or request.headers.get('User-Agent'),
        session_id=session.get('session_id'),
        risk_level=risk_level
    )
    db.session.add(log)
    db.session.commit()
    
    # Emit real-time notification
    socketio.emit('activity_update', {
        'action': action,
        'description': description,
        'timestamp': log.timestamp.isoformat()
    }, room=f'user_{user_id}')

@app.before_request
def before_request():
    """Security checks and session management"""
    if 'session_id' not in session:
        session['session_id'] = secrets.token_hex(32)
    
    # Detect suspicious activity
    if current_user.is_authenticated:
        suspicious = detect_suspicious_activity(current_user.id, request)
        if suspicious:
            log_security_event(current_user.id, 'SUSPICIOUS_ACTIVITY', 'high', 
                             suspicious['description'], request)

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

@app.route('/webauthn/register/begin', methods=['POST'])
@login_required
def webauthn_register_begin():
    """Start WebAuthn registration process"""
    try:
        options = generate_registration_options(
            rp_id=app.config['WEBAUTHN_RP_ID'],
            rp_name=app.config['WEBAUTHN_RP_NAME'],
            user_id=str(current_user.id).encode(),
            user_name=current_user.email,
            user_display_name=current_user.username,
        )
        
        session['webauthn_challenge'] = options.challenge
        return jsonify(options)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/webauthn/register/complete', methods=['POST'])
@login_required
def webauthn_register_complete():
    """Complete WebAuthn registration"""
    try:
        credential = RegistrationCredential.parse_raw(request.get_data())
        challenge = session.get('webauthn_challenge')
        
        if not challenge:
            return jsonify({'error': 'No challenge found'}), 400
        
        verification = verify_registration_response(
            credential=credential,
            expected_challenge=challenge,
            expected_origin=app.config['WEBAUTHN_ORIGIN'],
            expected_rp_id=app.config['WEBAUTHN_RP_ID'],
        )
        
        if verification.verified:
            # Store credential
            webauthn_cred = WebAuthnCredential(
                user_id=current_user.id,
                credential_id=base64.b64encode(verification.credential_id).decode(),
                public_key=base64.b64encode(verification.credential_public_key).decode(),
                device_name=request.json.get('device_name', 'Unknown Device')
            )
            
            db.session.add(webauthn_cred)
            current_user.webauthn_enabled = True
            db.session.commit()
            
            log_activity(current_user.id, 'WEBAUTHN_REGISTERED', 'WebAuthn credential registered')
            return jsonify({'verified': True})
        else:
            return jsonify({'error': 'Registration failed'}), 400
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

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
                user.last_login = datetime.utcnow()
                db.session.commit()
                log_activity(user.id, 'USER_LOGIN', f'User {user.username} logged in')
                return redirect(url_for('dashboard'))
        else:
            flash('Invalid credentials.', 'error')
    
    return render_template('login.html', form=form)

@app.route('/webauthn/login/begin', methods=['POST'])
def webauthn_login_begin():
    """Start WebAuthn authentication"""
    try:
        email = request.json.get('email')
        user = User.query.filter_by(email=email).first()
        
        if not user or not user.webauthn_enabled:
            return jsonify({'error': 'WebAuthn not enabled for this user'}), 400
        
        credentials = WebAuthnCredential.query.filter_by(user_id=user.id).all()
        credential_ids = [base64.b64decode(cred.credential_id) for cred in credentials]
        
        options = generate_authentication_options(
            rp_id=app.config['WEBAUTHN_RP_ID'],
            allow_credentials=credential_ids,
        )
        
        session['webauthn_challenge'] = options.challenge
        session['webauthn_user_id'] = user.id
        
        return jsonify(options)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/webauthn/login/complete', methods=['POST'])
def webauthn_login_complete():
    """Complete WebAuthn authentication"""
    try:
        credential = AuthenticationCredential.parse_raw(request.get_data())
        challenge = session.get('webauthn_challenge')
        user_id = session.get('webauthn_user_id')
        
        if not challenge or not user_id:
            return jsonify({'error': 'Invalid session state'}), 400
        
        user = User.query.get(user_id)
        webauthn_cred = WebAuthnCredential.query.filter_by(
            user_id=user_id,
            credential_id=base64.b64encode(credential.raw_id).decode()
        ).first()
        
        if not webauthn_cred:
            return jsonify({'error': 'Credential not found'}), 400
        
        verification = verify_authentication_response(
            credential=credential,
            expected_challenge=challenge,
            expected_origin=app.config['WEBAUTHN_ORIGIN'],
            expected_rp_id=app.config['WEBAUTHN_RP_ID'],
            credential_public_key=base64.b64decode(webauthn_cred.public_key),
            credential_current_sign_count=webauthn_cred.sign_count,
        )
        
        if verification.verified:
            login_user(user)
            user.last_login = datetime.utcnow()
            webauthn_cred.last_used = datetime.utcnow()
            webauthn_cred.sign_count = verification.new_sign_count
            db.session.commit()
            
            log_activity(user.id, 'WEBAUTHN_LOGIN', 'User logged in with WebAuthn')
            return jsonify({'verified': True, 'redirect': url_for('dashboard')})
        else:
            return jsonify({'error': 'Authentication failed'}), 400
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/dashboard')
@login_required
def dashboard():
    files = FileRecord.query.filter_by(user_id=current_user.id).order_by(FileRecord.upload_date.desc()).all()
    
    # Calculate storage statistics
    storage_stats = {
        'used': current_user.storage_used,
        'quota': current_user.storage_quota,
        'percentage': (current_user.storage_used / current_user.storage_quota) * 100,
        'files_count': len(files),
        'recent_uploads': len([f for f in files if f.upload_date > datetime.utcnow() - timedelta(days=7)])
    }
    
    # Get recent activities
    recent_activities = ActivityLog.query.filter_by(user_id=current_user.id)\
                                        .order_by(ActivityLog.timestamp.desc())\
                                        .limit(10).all()
    
    return render_template('dashboard.html', 
                         files=files, 
                         storage_stats=storage_stats,
                         recent_activities=recent_activities)

@app.route('/upload/chunked', methods=['POST'])
@login_required
def upload_chunked():
    """Handle chunked file uploads for large files"""
    try:
        chunk = request.files.get('chunk')
        chunk_number = int(request.form.get('chunkNumber', 0))
        total_chunks = int(request.form.get('totalChunks', 1))
        file_id = request.form.get('fileId')
        filename = request.form.get('filename')
        
        if not chunk:
            return jsonify({'error': 'No chunk provided'}), 400
        
        # Create file record on first chunk
        if chunk_number == 0:
            file_record = FileRecord(
                filename=secure_filename(filename),
                stored_filename=f"{datetime.now().strftime('%Y%m%d_%H%M%S_')}{secure_filename(filename)}",
                user_id=current_user.id,
                file_size=0,  # Will be updated when complete
                encryption_key='',  # Will be set when complete
                sync_status='uploading'
            )
            db.session.add(file_record)
            db.session.flush()
            file_id = file_record.id
        
        # Store chunk
        chunk_data = chunk.read()
        chunk_hash = hashlib.sha256(chunk_data).hexdigest()
        
        chunk_record = FileChunk(
            file_id=file_id,
            chunk_number=chunk_number,
            chunk_size=len(chunk_data),
            chunk_hash=chunk_hash,
            upload_status='uploaded'
        )
        
        # Save chunk to temporary location
        chunk_path = os.path.join(app.config['UPLOAD_FOLDER'], f'chunk_{file_id}_{chunk_number}')
        with open(chunk_path, 'wb') as f:
            f.write(chunk_data)
        
        db.session.add(chunk_record)
        db.session.commit()
        
        # If all chunks uploaded, reassemble file
        if chunk_number == total_chunks - 1:
            reassemble_file.delay(file_id, total_chunks)
        
        # Emit progress update
        progress = ((chunk_number + 1) / total_chunks) * 100
        socketio.emit('upload_progress', {
            'file_id': file_id,
            'progress': progress,
            'chunk': chunk_number + 1,
            'total': total_chunks
        }, room=f'user_{current_user.id}')
        
        return jsonify({
            'success': True,
            'file_id': file_id,
            'chunk_number': chunk_number,
            'progress': progress
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@celery.task
def reassemble_file(file_id, total_chunks):
    """Celery task to reassemble chunked file and encrypt it"""
    try:
        file_record = FileRecord.query.get(file_id)
        if not file_record:
            return
        
        # Reassemble chunks
        temp_path = os.path.join(app.config['UPLOAD_FOLDER'], f'temp_{file_record.stored_filename}')
        
        with open(temp_path, 'wb') as outfile:
            for i in range(total_chunks):
                chunk_path = os.path.join(app.config['UPLOAD_FOLDER'], f'chunk_{file_id}_{i}')
                if os.path.exists(chunk_path):
                    with open(chunk_path, 'rb') as chunk_file:
                        outfile.write(chunk_file.read())
                    os.remove(chunk_path)  # Clean up chunk
        
        # Encrypt the reassembled file
        encryption_key = generate_encryption_key()
        encrypted_path = os.path.join(app.config['UPLOAD_FOLDER'], file_record.stored_filename)
        
        encrypt_file(temp_path, encrypted_path, encryption_key)
        os.remove(temp_path)  # Clean up temp file
        
        # Update file record
        file_record.file_size = os.path.getsize(encrypted_path)
        file_record.encryption_key = base64.b64encode(encryption_key).decode('utf-8')
        file_record.file_hash = hashlib.sha256(open(encrypted_path, 'rb').read()).hexdigest()
        file_record.sync_status = 'synced'
        
        # AI categorization
        try:
            mime_type = magic.from_file(encrypted_path, mime=True)
            file_record.mime_type = mime_type
            file_record.category = categorize_file(file_record.filename, mime_type)
            file_record.tags = json.dumps(generate_tags(file_record.filename, mime_type))
        except:
            pass  # Continue without AI features if they fail
        
        # Update user storage
        user = User.query.get(file_record.user_id)
        user.storage_used += file_record.file_size
        
        db.session.commit()
        
        # Emit completion notification
        socketio.emit('upload_complete', {
            'file_id': file_id,
            'filename': file_record.filename,
            'size': file_record.file_size,
            'category': file_record.category
        }, room=f'user_{file_record.user_id}')
        
        log_activity(file_record.user_id, 'FILE_UPLOAD', f'Uploaded file: {file_record.filename}')
        
    except Exception as e:
        # Mark file as failed
        file_record = FileRecord.query.get(file_id)
        if file_record:
            file_record.sync_status = 'failed'
            db.session.commit()
        
        socketio.emit('upload_error', {
            'file_id': file_id,
            'error': str(e)
        }, room=f'user_{file_record.user_id}')

@app.route('/api/storage/stats')
@login_required
def storage_stats():
    """Real-time storage statistics API"""
    files = FileRecord.query.filter_by(user_id=current_user.id).all()
    
    # Category breakdown
    categories = {}
    for file in files:
        cat = file.category or 'other'
        categories[cat] = categories.get(cat, 0) + file.file_size
    
    # Recent activity
    recent_uploads = FileRecord.query.filter_by(user_id=current_user.id)\
                                   .filter(FileRecord.upload_date > datetime.utcnow() - timedelta(days=30))\
                                   .count()
    
    return jsonify({
        'storage_used': current_user.storage_used,
        'storage_quota': current_user.storage_quota,
        'files_count': len(files),
        'categories': categories,
        'recent_uploads': recent_uploads,
        'sync_status': 'online'  # This would be dynamic based on connection
    })

@app.route('/api/files/search')
@login_required
def search_files():
    """Search files with AI-powered filtering"""
    query = request.args.get('q', '')
    category = request.args.get('category', '')
    
    files_query = FileRecord.query.filter_by(user_id=current_user.id)
    
    if query:
        files_query = files_query.filter(
            FileRecord.filename.contains(query) |
            FileRecord.tags.contains(query)
        )
    
    if category:
        files_query = files_query.filter_by(category=category)
    
    files = files_query.order_by(FileRecord.upload_date.desc()).all()
    
    return jsonify([{
        'id': f.id,
        'filename': f.filename,
        'size': f.file_size,
        'category': f.category,
        'tags': json.loads(f.tags) if f.tags else [],
        'upload_date': f.upload_date.isoformat(),
        'sync_status': f.sync_status
    } for f in files])

# WebSocket events for real-time features
@socketio.on('connect')
@login_required
def on_connect():
    join_room(f'user_{current_user.id}')
    emit('connected', {'status': 'Connected to real-time updates'})

@socketio.on('disconnect')
@login_required
def on_disconnect():
    leave_room(f'user_{current_user.id}')

@socketio.on('sync_status')
@login_required
def handle_sync_status(data):
    """Handle sync status updates from client"""
    status = data.get('status', 'offline')
    
    # Update or create sync session
    sync_session = SyncSession.query.filter_by(
        user_id=current_user.id,
        session_id=session['session_id']
    ).first()
    
    if not sync_session:
        sync_session = SyncSession(
            user_id=current_user.id,
            session_id=session['session_id'],
            device_info=json.dumps(data.get('device_info', {}))
        )
        db.session.add(sync_session)
    
    sync_session.status = status
    sync_session.last_sync = datetime.utcnow()
    db.session.commit()
    
    emit('sync_status_updated', {'status': status})

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    socketio.run(app, debug=True, host='0.0.0.0', port=5000)
