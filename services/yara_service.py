import yara
import os
from flask import current_app

def yara_scan(file_path: str) -> dict:
    """
    Scans the file using YARA rules to detect custom malware signatures, 
    suspicious strings, PE headers, etc.
    """
    results = {
        "yara_hits": [],
        "risk_score_contribution": 0,
        "details": []
    }
    
    yara_rules_dir = current_app.config.get('YARA_RULES_DIR', os.path.join(os.getcwd(), 'rules'))
    
    if not os.path.exists(yara_rules_dir):
        results["details"].append("YARA rules directory not found. Skipping YARA scan.")
        return results
        
    try:
        # Collect all .yar files in the directory
        filepaths = {}
        for root, dirs, files in os.walk(yara_rules_dir):
            for file in files:
                if file.endswith('.yar') or file.endswith('.yara'):
                    filepaths[file] = os.path.join(root, file)
                    
        if not filepaths:
            results["details"].append("No YARA rules found in the directory.")
            return results
            
        # Compile rules
        rules = yara.compile(filepaths=filepaths)
        
        # Scan file
        matches = rules.match(file_path)
        
        if matches:
            for match in matches:
                results["yara_hits"].append(match.rule)
                results["details"].append(f"YARA Match: {match.rule} (Tags: {', '.join(match.tags)})")
                # YARA matches are severe indicators of malware/suspicious content
                results["risk_score_contribution"] += 40 
                
        else:
            results["details"].append("No YARA matches found.")
            
    except Exception as e:
        results["details"].append(f"YARA scan error: {str(e)}")
        
    return results
