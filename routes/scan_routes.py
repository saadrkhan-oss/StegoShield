from flask import Blueprint, request, jsonify
from flask_login import login_required, current_user
from services.scan_service import full_scan_report
import json
from models import db, ScanRecord

scan_bp = Blueprint("scan", __name__)

@scan_bp.route("/scan", methods=["POST"])
@login_required
def scan():
    uploaded = request.files.get("file")
    if not uploaded:
        return jsonify({"error": "No file uploaded"}), 400

    file_bytes = uploaded.read()
    filename = uploaded.filename

    report = full_scan_report(file_bytes, filename)
    
    # Save to database
    try:
        record = ScanRecord(
            filename=filename,
            operation_type='Scan',
            threat_score=report.get('threat_score', 0),
            risk_level=report.get('risk_level', 'Safe'),
            report_json=json.dumps(report),
            user_id=current_user.id
        )
        db.session.add(record)
        db.session.commit()
    except Exception as e:
        print(f"Error saving to DB: {e}")

    return jsonify(report)
