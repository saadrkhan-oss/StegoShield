import os

class Config:
    # Security: Load from environment variables, fallback to defaults for local dev
    SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
    
    # File Storage
    BASE_DIR = os.path.abspath(os.path.dirname(__file__))
    UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
    STEGO_FOLDER = os.path.join(UPLOAD_FOLDER, "stego")
    EXTRACTED_FOLDER = os.path.join(UPLOAD_FOLDER, "extracted")
    ENCRYPTED_FOLDER = os.path.join(UPLOAD_FOLDER, "encrypted")
    MAX_CONTENT_LENGTH = 50 * 1024 * 1024  # 50 MB
    
    # External Tool Paths (read from environment for cross-platform compatibility)
    YARA_RULES_DIR = os.path.join(BASE_DIR, "rules")
    EXIFTOOL_PATH = os.environ.get('EXIFTOOL_PATH', 'exiftool')
    STEGEXPOSE_PATH = os.environ.get('STEGEXPOSE_PATH', 'StegExpose.jar')
    CLAMAV_PATH = os.environ.get('CLAMAV_PATH', 'clamscan')
    BINWALK_CMD = os.environ.get('BINWALK_CMD', 'binwalk')
    ZSTEG_CMD = os.environ.get('ZSTEG_CMD', 'zsteg')

    # Admin Key
    ADMIN_KEY = os.environ.get('ADMIN_KEY', 'STEGO_ADMIN_2024')

    # Database Configuration (supports SQLite locally, PostgreSQL in production)
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', 'sqlite:///' + os.path.join(BASE_DIR, 'stego.db'))
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Ensure upload directories exist
    @staticmethod
    def init_app(app):
        for folder in [Config.UPLOAD_FOLDER, Config.STEGO_FOLDER, Config.EXTRACTED_FOLDER, Config.ENCRYPTED_FOLDER]:
            os.makedirs(folder, exist_ok=True)
