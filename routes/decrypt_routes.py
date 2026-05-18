from flask import Blueprint, request, jsonify, current_app
from flask_login import login_required, current_user
from werkzeug.utils import secure_filename
from services.scan_service import payload_scan_report
from services.stego_service import extract_secret
from utils.helpers import remove_file
import os
import re
import json
from models import db, ScanRecord

decrypt_bp = Blueprint("decrypt", __name__)

def is_valid_password(password):
    # 8-20 characters, at least one letter, one number, and one special character
    pattern = r"^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!%*#?&]{8,20}$"
    return re.match(pattern, password) is not None


@decrypt_bp.route("/decrypt", methods=["POST"])
@login_required
def decrypt():
    extracted_path = None
    try:
        stego = request.files.get("stego")
        password = request.form.get("password")

        if not stego or not password:
            return jsonify({"error": "Missing input"}), 400

        if not is_valid_password(password):
            return jsonify({"error": "Password must be 8-20 characters long, containing at least one letter, one number, and one special character (@$!%*#?&)."}), 400

        filename = secure_filename(stego.filename)
        path = f"{current_app.config['UPLOAD_FOLDER']}/{filename}"
        stego.save(path)

        # ---- Extract secret ----
        extracted_bytes, extracted_name = extract_secret(path, password)
        extracted_path = f"{current_app.config['EXTRACTED_FOLDER']}/{extracted_name}"

        # 2a. Check for empty file (Wrong password often yields garbage but maybe 0 len?)
        if os.path.getsize(extracted_path) == 0:
             return jsonify({
                "message": "Warning: Extracted file is empty. Check your password.",
                "extracted_filename": extracted_name,
                "scan_report": {"clam_status": "SKIPPED", "note": "Empty file"},
                "safe": True # It's empty, so it's safe?
            }), 200

        # ---- Automatic scan ----
        scan_result = payload_scan_report(extracted_bytes, extracted_name)
        
        # Save to database
        try:
            record = ScanRecord(
                filename=filename, # The stego file that was decrypted
                operation_type='Decrypt',
                threat_score=scan_result.get('threat_score', 0),
                risk_level=scan_result.get('risk_level', 'Safe'),
                report_json=json.dumps(scan_result),
                user_id=current_user.id
            )
            db.session.add(record)
            db.session.commit()
        except Exception as e:
            print(f"Error saving to DB: {e}")

        # Check security status
        # Flag if Risk Level is Dangerous or Critical
        is_infected = (scan_result.get("risk_level") in ["Dangerous", "Critical"])
        
        if is_infected:
            # WARNING: Virus detected.
             return jsonify({
                "message": "Security Alert: Decrypted file is flagged as suspicious/infected, but kept.",
                "extracted_filename": extracted_name,
                "scan_report": scan_result,
                "safe": False
            }), 200

        return jsonify({
            "message": f"Decryption successful. Risk Level: {scan_result.get('risk_level')}.",
            "extracted_filename": extracted_name,
            "scan_report": scan_result,
            "safe": True
        })

    except Exception as e:
        # Cleanup if something failed
        if extracted_path:
            remove_file(extracted_path)
        return jsonify({"error": str(e)}), 500
