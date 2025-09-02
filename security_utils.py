"""
Security utilities for threat detection and monitoring
"""
from datetime import datetime, timedelta
from collections import defaultdict
import json
import hashlib
import requests
from flask import request
from models_sqlite import ActivityLog, db
import bcrypt

# In-memory cache for rate limiting and suspicious activity detection
activity_cache = defaultdict(list)
failed_attempts = defaultdict(int)

def detect_suspicious_activity(user_id, request_obj):
    """
    Detect suspicious activity patterns
    """
    current_time = datetime.utcnow()
    ip_address = request_obj.remote_addr
    user_agent = request_obj.headers.get('User-Agent', '')
    
    # Check for rapid requests (potential bot activity)
    user_requests = activity_cache[f"user_{user_id}"]
    user_requests.append(current_time)
    
    # Keep only requests from last 5 minutes
    cutoff_time = current_time - timedelta(minutes=5)
    user_requests[:] = [req_time for req_time in user_requests if req_time > cutoff_time]
    
    # Suspicious if more than 100 requests in 5 minutes
    if len(user_requests) > 100:
        return {
            'type': 'RAPID_REQUESTS',
            'description': f'User made {len(user_requests)} requests in 5 minutes',
            'severity': 'high'
        }
    
    # Check for multiple IP addresses
    ip_requests = activity_cache[f"ip_{ip_address}"]
    ip_requests.append(current_time)
    ip_requests[:] = [req_time for req_time in ip_requests if req_time > cutoff_time]
    
    # Check recent activities for this user from different IPs
    recent_activities = ActivityLog.query.filter(
        ActivityLog.user_id == user_id,
        ActivityLog.timestamp > current_time - timedelta(hours=1)
    ).all()
    
    unique_ips = set(activity.ip_address for activity in recent_activities if activity.ip_address)
    if len(unique_ips) > 3:
        return {
            'type': 'MULTIPLE_IPS',
            'description': f'User accessed from {len(unique_ips)} different IPs in 1 hour',
            'severity': 'medium'
        }
    
    # Check for unusual user agent patterns
    if not user_agent or len(user_agent) < 10:
        return {
            'type': 'SUSPICIOUS_USER_AGENT',
            'description': 'Request with suspicious or missing user agent',
            'severity': 'low'
        }
    
    # Check for known malicious patterns in user agent
    malicious_patterns = ['bot', 'crawler', 'scanner', 'hack', 'exploit']
    if any(pattern in user_agent.lower() for pattern in malicious_patterns):
        return {
            'type': 'MALICIOUS_USER_AGENT',
            'description': f'Potentially malicious user agent: {user_agent[:100]}',
            'severity': 'high'
        }
    
    return None

def log_security_event(user_id, event_type, severity, description, request_obj, metadata=None):
    """
    Log a security event
    """
    # Create activity log entry for security event
    log = ActivityLog(
        user_id=user_id,
        action=f'SECURITY_{event_type}'
    )
    log.set_description(description)
    if request_obj:
        log.set_ip_address(request_obj.remote_addr or 'unknown')
    
    db.session.add(log)
    db.session.commit()
    
    # If high severity, could trigger additional actions
    if severity in ['high', 'critical']:
        handle_high_severity_event(log)

def handle_high_severity_event(event):
    """
    Handle high severity security events
    """
    # Could implement:
    # - Email notifications
    # - Temporary account locks
    # - IP blocking
    # - Admin notifications
    pass

def validate_file_integrity(file_path, expected_hash):
    """
    Validate file integrity using SHA-256 hash
    """
    try:
        with open(file_path, 'rb') as f:
            file_hash = hashlib.sha256(f.read()).hexdigest()
        return file_hash == expected_hash
    except:
        return False

def check_ip_reputation(ip_address):
    """
    Check IP reputation against threat intelligence feeds
    This is a placeholder - would integrate with real threat intel APIs
    """
    # Known malicious IP ranges (example)
    malicious_ranges = [
        '192.168.1.100',  # Example
        '10.0.0.50'       # Example
    ]
    
    if ip_address in malicious_ranges:
        return {
            'is_malicious': True,
            'reason': 'Known malicious IP',
            'confidence': 'high'
        }
    
    # Could integrate with services like:
    # - VirusTotal API
    # - AbuseIPDB
    # - Shodan
    # - Custom threat feeds
    
    return {
        'is_malicious': False,
        'reason': 'No threat indicators found',
        'confidence': 'medium'
    }

def generate_security_report(user_id, days=30):
    """
    Generate security report for a user
    """
    cutoff_date = datetime.utcnow() - timedelta(days=days)
    
    # Get security-related activities from ActivityLog
    events = ActivityLog.query.filter(
        ActivityLog.user_id == user_id,
        ActivityLog.timestamp > cutoff_date,
        ActivityLog.action.like('SECURITY_%')
    ).all()
    
    # Get activities
    activities = ActivityLog.query.filter(
        ActivityLog.user_id == user_id,
        ActivityLog.timestamp > cutoff_date
    ).all()
    
    # Analyze patterns
    event_types = defaultdict(int)
    severity_counts = defaultdict(int)
    ip_addresses = set()
    
    for event in events:
        event_types[event.event_type] += 1
        severity_counts[event.severity] += 1
    
    for activity in activities:
        if activity.ip_address:
            ip_addresses.add(activity.ip_address)
    
    report = {
        'period_days': days,
        'total_events': len(events),
        'total_activities': len(activities),
        'event_types': dict(event_types),
        'severity_breakdown': dict(severity_counts),
        'unique_ip_addresses': len(ip_addresses),
        'risk_score': calculate_risk_score(events, activities),
        'recommendations': generate_security_recommendations(events, activities)
    }
    
    return report

def calculate_risk_score(events, activities):
    """
    Calculate a risk score based on security events and activities
    """
    score = 0
    
    # Base score from events
    for event in events:
        if event.severity == 'critical':
            score += 10
        elif event.severity == 'high':
            score += 5
        elif event.severity == 'medium':
            score += 2
        elif event.severity == 'low':
            score += 1
    
    # Adjust based on activity patterns
    if len(activities) > 1000:  # Very active user
        score += 2
    
    # Normalize to 0-100 scale
    return min(score, 100)

def generate_security_recommendations(events, activities):
    """
    Generate security recommendations based on analysis
    """
    recommendations = []
    
    # Check for high-risk events
    high_risk_events = [e for e in events if e.severity in ['high', 'critical']]
    if high_risk_events:
        recommendations.append({
            'type': 'critical',
            'message': f'You have {len(high_risk_events)} high-risk security events. Review your account activity.',
            'action': 'review_security_events'
        })
    
    # Check for multiple IP usage
    unique_ips = set(a.ip_address for a in activities if a.ip_address)
    if len(unique_ips) > 5:
        recommendations.append({
            'type': 'warning',
            'message': f'Your account was accessed from {len(unique_ips)} different IP addresses.',
            'action': 'enable_2fa'
        })
    
    # Check for 2FA status (would need user object)
    recommendations.append({
        'type': 'info',
        'message': 'Enable two-factor authentication for enhanced security.',
        'action': 'setup_2fa'
    })
    
    # Check for WebAuthn
    recommendations.append({
        'type': 'info',
        'message': 'Consider using passwordless login with biometrics for maximum security.',
        'action': 'setup_webauthn'
    })
    
    return recommendations

def hash_password_secure(password):
    """Hash password using bcrypt"""
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

def verify_password_secure(password, hashed):
    """Verify password against bcrypt hash"""
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

def log_activity(user_id, action, description, request_obj=None):
    """Log user activity"""
    log = ActivityLog(
        user_id=user_id,
        action=action
    )
    log.set_description(description)
    
    if request_obj:
        log.set_ip_address(request_obj.remote_addr or 'unknown')
    
    db.session.add(log)
    db.session.commit()

def encrypt_sensitive_data(data, key):
    """
    Encrypt sensitive data for storage
    """
    from cryptography.fernet import Fernet
    f = Fernet(key)
    return f.encrypt(data.encode()).decode()

def decrypt_sensitive_data(encrypted_data, key):
    """
    Decrypt sensitive data
    """
    from cryptography.fernet import Fernet
    f = Fernet(key)
    return f.decrypt(encrypted_data.encode()).decode()

def generate_secure_token(length=32):
    """
    Generate a cryptographically secure token
    """
    import secrets
    return secrets.token_urlsafe(length)

def validate_csrf_token(token, session_token):
    """
    Validate CSRF token
    """
    return token == session_token

def sanitize_input(input_string):
    """
    Sanitize user input to prevent XSS and injection attacks
    """
    import html
    import re
    
    # HTML escape
    sanitized = html.escape(input_string)
    
    # Remove potentially dangerous patterns
    dangerous_patterns = [
        r'<script.*?>.*?</script>',
        r'javascript:',
        r'vbscript:',
        r'onload=',
        r'onerror=',
        r'onclick='
    ]
    
    for pattern in dangerous_patterns:
        sanitized = re.sub(pattern, '', sanitized, flags=re.IGNORECASE)
    
    return sanitized
