import subprocess
import os
from flask import current_app

def analyze_metadata(file_path: str) -> dict:
    """
    Analyzes image metadata using ExifTool to detect anomalies.
    """
    results = {
        "metadata": {},
        "suspicious_tags": [],
        "risk_score_contribution": 0
    }
    
    exiftool_path = current_app.config.get('EXIFTOOL_PATH', r'C:\exiftool\exiftool.exe')
    
    if not os.path.exists(exiftool_path):
        results["suspicious_tags"].append("ExifTool not found. Metadata analysis skipped.")
        return results

    try:
        # Run exiftool in JSON output format
        process = subprocess.run([exiftool_path, '-json', file_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        
        if process.returncode == 0 and process.stdout:
            import json
            metadata_list = json.loads(process.stdout)
            if metadata_list:
                metadata = metadata_list[0]
                results["metadata"] = metadata
                
                # Check for suspicious tags or anomalies
                suspicious_keys = ['Comment', 'UserComment', 'Copyright', 'Warning']
                
                for key in suspicious_keys:
                    if key in metadata:
                        val = str(metadata[key])
                        if len(val) > 100: # Unusually long comments
                            results["suspicious_tags"].append(f"Unusually long {key} field detected ({len(val)} chars).")
                            results["risk_score_contribution"] += 10
                            
                # Check if it has Warning tags
                if 'Warning' in metadata:
                    results["suspicious_tags"].append(f"ExifTool Warning: {metadata['Warning']}")
                    results["risk_score_contribution"] += 15
                    
    except Exception as e:
        results["suspicious_tags"].append(f"Metadata analysis error: {str(e)}")

    return results
