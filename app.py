from flask import Flask
from config import Config
from flask_login import LoginManager

# Import blueprints
from routes.encrypt_routes import encrypt_bp
from routes.decrypt_routes import decrypt_bp
from routes.scan_routes import scan_bp
from routes.main_routes import main_bp
from routes.auth_routes import auth_bp
from models import db, User

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)
    Config.init_app(app)

    # Initialize database
    db.init_app(app)

    # Initialize Login Manager
    login_manager = LoginManager()
    login_manager.login_view = 'auth.login'
    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    # Register blueprints
    app.register_blueprint(encrypt_bp)
    app.register_blueprint(decrypt_bp)
    app.register_blueprint(scan_bp)
    app.register_blueprint(main_bp)
    app.register_blueprint(auth_bp)

    with app.app_context():
        db.create_all()
        # Migration: Add user_id column if it doesn't exist (SQLite doesn't support easy migrations)
        try:
            import sqlite3
            import os
            db_uri = app.config['SQLALCHEMY_DATABASE_URI']
            if db_uri.startswith('sqlite:///'):
                db_path = db_uri.replace('sqlite:///', '')
                if not os.path.isabs(db_path):
                    db_path = os.path.join(os.getcwd(), db_path)
                
                conn = sqlite3.connect(db_path)
                cursor = conn.cursor()
                cursor.execute("PRAGMA table_info(scan_record);")
                columns = [column[1] for column in cursor.fetchall()]
                if 'user_id' not in columns:
                    print("Auto-migration: Adding user_id to scan_record")
                    cursor.execute("ALTER TABLE scan_record ADD COLUMN user_id INTEGER REFERENCES user(id);")
                    conn.commit()
                conn.close()
        except Exception as e:
            print(f"Auto-migration failed: {e}")

    return app

app = create_app()

if __name__ == "__main__":
    app.run(debug=True)
