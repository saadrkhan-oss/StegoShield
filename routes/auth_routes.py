from flask import Blueprint, render_template, redirect, url_for, request, flash
from flask_login import login_user, logout_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
from models import db, User

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
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
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'danger')
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
