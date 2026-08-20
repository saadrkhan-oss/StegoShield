from flask import Blueprint, render_template, redirect, url_for, request, flash
from flask_login import login_user, logout_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
import re
from models import db, User

auth_bp = Blueprint('auth', __name__)

def validate_username_and_password(username, password, confirm_password):
    errors = []
    
    # 1. Username (Email) Validation
    if not username:
        errors.append("Username/Email is required.")
    elif len(username) > 150:
        errors.append("Username/Email must be 150 characters or less.")
    else:
        email_regex = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
        if not re.match(email_regex, username):
            errors.append("Username must be a valid email address (e.g., operator@domain.com).")
            
    # 2. Password Confirmation Validation
    if password != confirm_password:
        errors.append("Passwords do not match.")
        
    # 3. Password Complexity Validation
    if not password:
        errors.append("Password is required.")
    else:
        if len(password) < 8:
            errors.append("Password must be at least 8 characters long.")
        if not any(c.isupper() for c in password):
            errors.append("Password must contain at least one uppercase letter.")
        if not any(c.islower() for c in password):
            errors.append("Password must contain at least one lowercase letter.")
        if not any(c.isdigit() for c in password):
            errors.append("Password must contain at least one number.")
        if not any(c in "@$!%*?&_-" for c in password):
            errors.append("Password must contain at least one special character (e.g., @$!%*?&_-).")
            
    return errors

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter(db.func.lower(User.username) == username.lower()).first()
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            if user.is_admin:
                return redirect(url_for('main.dashboard'))
            else:
                return redirect(url_for('main.upload'))
        else:
            flash('Invalid username or password', 'danger')
            
    return render_template('login.html')

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        # Run validations
        validation_errors = validate_username_and_password(username, password, confirm_password)
        if validation_errors:
            for error in validation_errors:
                flash(error, 'danger')
        # Check if user already exists (case-insensitive)
        elif User.query.filter(db.func.lower(User.username) == username.lower()).first():
            flash('Username/Email already exists', 'danger')
        else:
            admin_key = request.form.get('admin_key')
            from flask import current_app
            # First user is admin, or anyone with the secret Admin Key
            is_admin = (User.query.count() == 0) or (admin_key == current_app.config.get('ADMIN_KEY', 'STEGO_ADMIN_2024'))
            
            new_user = User(
                username=username, 
                password_hash=generate_password_hash(password, method='pbkdf2:sha256'),
                is_admin=is_admin
            )
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('auth.login'))
            
    return render_template('register.html')

@auth_bp.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))
