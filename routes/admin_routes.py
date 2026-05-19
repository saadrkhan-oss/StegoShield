from flask import Blueprint, render_template, request, jsonify, abort
from flask_login import login_required, current_user
from werkzeug.security import generate_password_hash
from models import db, User

admin_bp = Blueprint('admin', __name__)

def admin_required(f):
    """Decorator: Block non-admin users from accessing admin routes."""
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            abort(403)
        return f(*args, **kwargs)
    return decorated_function


@admin_bp.route('/admin/users')
@login_required
@admin_required
def user_management():
    """Render the user management page (admin only)."""
    return render_template('users.html')


@admin_bp.route('/api/users', methods=['GET'])
@login_required
@admin_required
def get_users():
    """API: Return all registered users."""
    users = User.query.order_by(User.id.asc()).all()
    return jsonify([{
        'id': u.id,
        'username': u.username,
        'is_admin': u.is_admin,
        'scan_count': len(u.scans)
    } for u in users])


@admin_bp.route('/api/users', methods=['POST'])
@login_required
@admin_required
def add_user():
    """API: Create a new user (admin only)."""
    data = request.get_json()
    username = data.get('username', '').strip()
    password = data.get('password', '').strip()
    is_admin = data.get('is_admin', False)

    if not username or not password:
        return jsonify({'error': 'Username and password are required.'}), 400

    if len(password) < 8:
        return jsonify({'error': 'Password must be at least 8 characters.'}), 400

    if User.query.filter_by(username=username).first():
        return jsonify({'error': 'Username already exists.'}), 409

    new_user = User(
        username=username,
        password_hash=generate_password_hash(password, method='pbkdf2:sha256'),
        is_admin=bool(is_admin)
    )
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': f'User "{username}" created successfully.', 'id': new_user.id}), 201


@admin_bp.route('/api/users/<int:user_id>', methods=['DELETE'])
@login_required
@admin_required
def delete_user(user_id):
    """API: Delete a user (admin only). Cannot delete yourself."""
    if user_id == current_user.id:
        return jsonify({'error': 'You cannot delete your own account.'}), 400

    user = User.query.get_or_404(user_id)
    username = user.username
    db.session.delete(user)
    db.session.commit()

    return jsonify({'message': f'User "{username}" has been deleted.'})


@admin_bp.route('/api/users/<int:user_id>/toggle-admin', methods=['PUT'])
@login_required
@admin_required
def toggle_admin(user_id):
    """API: Toggle admin status of a user. Cannot demote yourself."""
    if user_id == current_user.id:
        return jsonify({'error': 'You cannot change your own admin status.'}), 400

    user = User.query.get_or_404(user_id)
    user.is_admin = not user.is_admin
    db.session.commit()

    status = 'Admin' if user.is_admin else 'Standard User'
    return jsonify({'message': f'"{user.username}" is now {status}.', 'is_admin': user.is_admin})
