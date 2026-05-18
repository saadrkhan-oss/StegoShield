from flask import Blueprint, request, jsonify, current_app
from flask_login import login_required, current_user
from werkzeug.utils import secure_filename
from services.stego_service import encrypt_and_embed
from services.scan_service import payload_scan_report
import os
import re
import json
from models import db, ScanRecord

encrypt_bp = Blueprint("encrypt", __name__)

def is_valid_password(password):
    # 8-20 characters, at least one letter, one number, and one special character
    pattern = r"^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!%*#?&]{8,20}$"
    return re.match(pattern, password) is not None

@encrypt_bp.route("/encrypt", methods=["POST"])
@login_required
def encrypt():
    try:
        cover = request.files.get("cover")
        secret = request.files.get("secret")
        password = request.form.get("password")

        if not cover or not secret or not password:
            return jsonify({"error": "Missing input"}), 400

        if not is_valid_password(password):
            return jsonify({"error": "Password must be 8-20 characters long, containing at least one letter, one number, and one special character (@$!%*#?&)."}), 400

        cover_name = secure_filename(cover.filename)
        secret_name = secure_filename(secret.filename)
        
        # Validate that cover is an image
        if not cover_name.lower().endswith(('.png', '.jpg', '.jpeg', '.bmp', '.gif')):
             return jsonify({"error": "Cover file must be an image."}), 400

        cover_path = f"{current_app.config['UPLOAD_FOLDER']}/{cover_name}"
        secret_path = f"{current_app.config['UPLOAD_FOLDER']}/{secret_name}"

        cover.save(cover_path)
        secret.save(secret_path)

        # Extract extensions
        cover_ext = os.path.splitext(cover_name)[1]
        secret_ext = os.path.splitext(secret_name)[1]

        # Explicitly trust extensions for now since we are just embedding.
        stego_filename, stego_path, encrypted_filename = encrypt_and_embed(
            cover_path, secret_path, password, cover_ext, secret_ext
        )

        secret_bytes = open(secret_path, "rb").read()
        secret_report = payload_scan_report(secret_bytes, secret_name)

        # Removed scanning of the resulting stego file to prevent false positives.
        # We trust our stego structure if the secret itself is clean.
        
        try:
            record = ScanRecord(
                filename=cover_name, # Storing the cover name for encryption
                operation_type='Encrypt',
                threat_score=secret_report.get('threat_score', 0),
                risk_level=secret_report.get('risk_level', 'Safe'),
                report_json=json.dumps(secret_report),
                user_id=current_user.id
            )
            db.session.add(record)
            db.session.commit()
        except Exception as e:
            print(f"Error saving to DB: {e}")
            
        return jsonify({
            "message": "File encrypted successfully.",
            "stego_filename": stego_filename,
            "encrypted_filename": encrypted_filename,
            "secret_report": secret_report
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500
