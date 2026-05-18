import mimetypes
import math
import subprocess
import os
from flask import current_app
from utils.helpers import temp_write

# Import new layers
from services.validation_service import validate_image
from services.metadata_service import analyze_metadata
from services.steganalysis_service import analyze_image_statistics
from services.extraction_service import attempt_extraction
from services.yara_service import yara_scan
from services.ai_service import ai_threat_classification

def calculate_entropy(data: bytes) -> float:
    """Shannon entropy."""
    if not data:
        return 0.0

    freq = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1

    length = len(data)
    entropy = 0

    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)

    return round(entropy, 4)


def clamav_scan(file_path: str):
    """Runs ClamAV and returns its output."""
    clamscan = r"C:\clamav\clamscan.exe"

    if not os.path.exists(clamscan):
        return "ClamAV not installed", "NOT FOUND"

    try:
        result = subprocess.run(
            [clamscan, file_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        output = result.stdout

        if "FOUND" in output:
            return output, "INFECTED"
        else:
            return output, "CLEAN"

    except Exception as e:
        return str(e), "SCAN ERROR"


def full_scan_report(file_bytes: bytes, filename: str):
    """
    Orchestrates the 10-layer advanced scanning pipeline and calculates the final Threat Score.
    """
    report = {
        "filename": filename,
        "layers": {},
        "threat_score": 0,
        "risk_level": "Safe",
        "summary": []
    }
    
    total_score = 0
    
    # Save file temporarily for tools that require a file path
    temp_path = temp_write(file_bytes, filename)
    
    try:
        # Layer 1: Validation (MIME, Magic Bytes, Pillow structure)
        val_res = validate_image(file_bytes, filename)
        report["layers"]["validation"] = val_res
        if not val_res["is_valid"]:
            total_score += 30
            report["summary"].append("File failed structural validation.")
            
        # Layer 2: EXIF Metadata Analysis
        meta_res = analyze_metadata(temp_path)
        report["layers"]["metadata"] = meta_res
        total_score += meta_res.get("risk_score_contribution", 0)
        
        # Layer 3: Steganalysis (OpenCV)
        steg_res = analyze_image_statistics(temp_path)
        report["layers"]["steganalysis"] = steg_res
        total_score += steg_res.get("risk_score_contribution", 0)
        
        # Layer 4: Entropy Analysis
        entropy = calculate_entropy(file_bytes)
        entropy_res = {"entropy": entropy, "details": []}
        if entropy > 7.5: # Highly encrypted/compressed
            entropy_res["details"].append(f"High entropy ({entropy}) suggests encrypted hidden payload.")
            total_score += 20
        report["layers"]["entropy"] = entropy_res
        
        # Layer 5: Extraction
        extraction_dir = os.path.join(current_app.config['EXTRACTED_FOLDER'], 'auto_extract')
        ext_res = attempt_extraction(temp_path, extraction_dir)
        report["layers"]["extraction"] = ext_res
        total_score += ext_res.get("risk_score_contribution", 0)
        
        # Layer 6: YARA Scan
        yara_res = yara_scan(temp_path)
        report["layers"]["yara"] = yara_res
        total_score += yara_res.get("risk_score_contribution", 0)
        
        # Layer 7: ClamAV Scan
        clam_output, clam_status = clamav_scan(temp_path)
        report["layers"]["clamav"] = {
            "status": clam_status,
            "output": clam_output
        }
        if clam_status == "INFECTED":
            total_score += 50
            
        # Layer 8: AI/ML Risk Scoring
        ai_res = ai_threat_classification(temp_path)
        report["layers"]["ai"] = ai_res
        total_score += ai_res.get("risk_score_contribution", 0)
        
        # Final Layer 9 & 10: Threat Scoring & Report
        # Cap score at 100
        report["threat_score"] = min(total_score, 100)
        
        if report["threat_score"] <= 20:
            report["risk_level"] = "Safe"
        elif report["threat_score"] <= 40:
            report["risk_level"] = "Suspicious"
        elif report["threat_score"] <= 70:
            report["risk_level"] = "Dangerous"
        else:
            report["risk_level"] = "Critical"
            
    finally:
        # Cleanup temp file
        if os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except:
                pass
            
    return report

def payload_scan_report(file_bytes: bytes, filename: str):
    """
    Scans the extracted payload (which may not be an image).
    Only runs relevant malware checks (YARA, ClamAV) to avoid false positives.
    """
    report = {
        "filename": filename,
        "layers": {},
        "threat_score": 0,
        "risk_level": "Safe",
        "summary": []
    }
    
    total_score = 0
    temp_path = temp_write(file_bytes, filename)
    
    try:
        # Layer 1: YARA Scan
        yara_res = yara_scan(temp_path)
        report["layers"]["yara"] = yara_res
        total_score += yara_res.get("risk_score_contribution", 0)
        
        # Layer 2: ClamAV Scan
        clam_output, clam_status = clamav_scan(temp_path)
        report["layers"]["clamav"] = {
            "status": clam_status,
            "output": clam_output
        }
        if clam_status == "INFECTED":
            total_score += 50
            
        report["threat_score"] = min(total_score, 100)
        
        if report["threat_score"] == 0:
            report["risk_level"] = "Safe"
        elif report["threat_score"] <= 40:
            report["risk_level"] = "Suspicious"
        elif report["threat_score"] <= 70:
            report["risk_level"] = "Dangerous"
        else:
            report["risk_level"] = "Critical"
            
    finally:
        if os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except:
                pass
            
    return report
