from flask import Blueprint, render_template, send_from_directory, current_app, abort, jsonify, redirect, url_for
import os
from models import ScanRecord, db
from sqlalchemy import func
from sqlalchemy.orm import joinedload
from flask_login import login_required, current_user

main_bp = Blueprint("main", __name__)

@main_bp.route("/")
@login_required
def dashboard():
    if not current_user.is_admin:
        return redirect(url_for('main.upload'))
    return render_template("dashboard.html")

@main_bp.route("/upload")
@login_required
def upload():
    return render_template("upload.html")

@main_bp.route("/history")
@login_required
def history():
    return render_template("history.html")

@main_bp.route("/api/stats")
@login_required
def get_stats():
    if not current_user.is_admin:
        return jsonify({"error": "Unauthorized"}), 403
    
    try:
        # Gather statistics for the dashboard
        total_scans = ScanRecord.query.count()
        
        # Risk distribution
        risk_counts = db.session.query(ScanRecord.risk_level, func.count(ScanRecord.id)).group_by(ScanRecord.risk_level).all()
        risk_dist = {str(r[0]) if r[0] is not None else "Unknown": r[1] for r in risk_counts}
        
        # Operation types
        op_counts = db.session.query(ScanRecord.operation_type, func.count(ScanRecord.id)).group_by(ScanRecord.operation_type).all()
        op_dist = {str(r[0]) if r[0] is not None else "Unknown": r[1] for r in op_counts}
        
        # Recent activity
        recent = ScanRecord.query.order_by(ScanRecord.timestamp.desc()).limit(10).all()
        recent_activity = [r.to_dict(summary_only=True) for r in recent]
        
        # Calculate basics
        malware_detected = risk_dist.get('Critical', 0) + risk_dist.get('Dangerous', 0)
        safe_files = risk_dist.get('Safe', 0)
        avg_score = db.session.query(func.avg(ScanRecord.threat_score)).scalar() or 0

        return jsonify({
            'total_scans': total_scans,
            'malware_detected': malware_detected,
            'safe_files': safe_files,
            'avg_score': round(float(avg_score), 1),
            'risk_distribution': risk_dist,
            'operation_distribution': op_dist,
            'recent_activity': recent_activity
        })
    except Exception as e:
        print(f"API ERROR [get_stats]: {str(e)}")
        return jsonify({"error": "Failed to load statistics", "details": str(e)}), 500

@main_bp.route("/api/history")
@login_required
def get_history():
    try:
        if current_user.is_admin:
            records = ScanRecord.query.order_by(ScanRecord.timestamp.desc()).limit(100).all()
        else:
            records = ScanRecord.query.filter_by(user_id=current_user.id).order_by(ScanRecord.timestamp.desc()).limit(100).all()
        return jsonify([r.to_dict(summary_only=True) for r in records])
    except Exception as e:
        print(f"API ERROR [get_history]: {str(e)}")
        return jsonify({"error": "Failed to load history", "details": str(e)}), 500

@main_bp.route("/api/report/<int:report_id>")
@login_required
def get_report_details(report_id):
    record = ScanRecord.query.get_or_404(report_id)
    # Check authorization: Admin can see all, users only theirs
    if not current_user.is_admin and record.user_id != current_user.id:
        abort(403)
    return jsonify(record.to_dict(summary_only=False))

@main_bp.route("/download/<filename>")
def download_file(filename):
    # Check multiple locations since we split the folders
    directories = [
        current_app.config["EXTRACTED_FOLDER"],
        current_app.config["STEGO_FOLDER"],
        current_app.config["ENCRYPTED_FOLDER"],
        current_app.config["UPLOAD_FOLDER"]
    ]
    
    for directory in directories:
        # Check if file exists in this directory before trying to send
        if os.path.exists(os.path.join(directory, filename)):
            return send_from_directory(directory, filename, as_attachment=True)
            
    # If not found in any
    abort(404)
