from flask import Blueprint, render_template, request, flash, redirect, url_for, jsonify
from flask_login import login_required, current_user
from datetime import datetime, timedelta
from models_sqlite import db, User
import os

subscription_bp = Blueprint('subscription', __name__)

@subscription_bp.route('/subscription')
@login_required
def subscription():
    """Subscription management page"""
    return render_template('subscription.html', user=current_user)

@subscription_bp.route('/upgrade', methods=['POST'])
@login_required
def upgrade():
    """Upgrade to premium subscription"""
    try:
        # In a real app, this would integrate with payment processing
        # For demo purposes, we'll just upgrade the user
        current_user.subscription_type = 'premium'
        current_user.subscription_expires = datetime.utcnow() + timedelta(days=30)
        db.session.commit()
        
        flash('Successfully upgraded to Premium! You now have unlimited file uploads.', 'success')
        return redirect(url_for('subscription.subscription'))
    except Exception as e:
        flash('Failed to upgrade subscription. Please try again.', 'error')
        return redirect(url_for('subscription.subscription'))

@subscription_bp.route('/cancel', methods=['POST'])
@login_required
def cancel():
    """Cancel premium subscription"""
    try:
        current_user.subscription_type = 'free'
        current_user.subscription_expires = None
        db.session.commit()
        
        flash('Premium subscription cancelled. You are now on the free plan (50 files limit).', 'info')
        return redirect(url_for('subscription.subscription'))
    except Exception as e:
        flash('Failed to cancel subscription. Please try again.', 'error')
        return redirect(url_for('subscription.subscription'))
