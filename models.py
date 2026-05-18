from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime
import json

db = SQLAlchemy()

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    
    # Relationship to ScanRecord
    scans = db.relationship('ScanRecord', backref='user', lazy=True)

class ScanRecord(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    operation_type = db.Column(db.String(50), nullable=False) # e.g., 'Scan', 'Decrypt', 'Encrypt'
    threat_score = db.Column(db.Integer, default=0)
    risk_level = db.Column(db.String(50), default='Safe')
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    report_json = db.Column(db.Text, nullable=True) # JSON string of the detailed report
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True) # Optional for backward compatibility

    def to_dict(self, summary_only=True):
        data = {
            'id': self.id,
            'filename': self.filename,
            'operation_type': self.operation_type,
            'threat_score': self.threat_score,
            'risk_level': self.risk_level,
            'timestamp': self.timestamp.isoformat() + 'Z',
            'username': self.user.username if self.user else 'Unknown'
        }
        if not summary_only:
            try:
                data['report_json'] = json.loads(self.report_json) if self.report_json else {}
            except Exception:
                data['report_json'] = {"error": "Corrupted forensic data"}
        return data
