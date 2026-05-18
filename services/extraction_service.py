import subprocess
import os
from flask import current_app

def attempt_extraction(file_path: str, output_dir: str) -> dict:
    """
    Attempts to extract hidden payloads using Binwalk and zsteg.
    (Steghide requires password, typically handled separately, but we can do a blind extraction attempt).
    """
    results = {
        "payload_extracted": False,
        "tools_used": [],
        "risk_score_contribution": 0,
        "details": []
    }
    
    # Ensure output dir exists
    if not os.path.exists(output_dir):
        os.makedirs(output_dir, exist_ok=True)
        
    binwalk_cmd = current_app.config.get('BINWALK_CMD', 'binwalk')
    zsteg_cmd = current_app.config.get('ZSTEG_CMD', 'zsteg')

    # 1. Binwalk (Look for embedded files)
    try:
        # Run binwalk signature scan
        bw_process = subprocess.run([binwalk_cmd, file_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        results["tools_used"].append("Binwalk")
        if bw_process.returncode == 0:
            output = bw_process.stdout
            lines = output.split('\n')
            # Binwalk output usually has a header. If there are more than 3-4 lines, it found something.
            if len([l for l in lines if l.strip() and not l.startswith('DECIMAL')]) > 0:
                # To actually extract: binwalk -e file_path -C output_dir
                ext_process = subprocess.run([binwalk_cmd, '-e', file_path, '-C', output_dir], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                results["payload_extracted"] = True
                results["details"].append("Binwalk detected and extracted embedded files.")
                results["risk_score_contribution"] += 25
    except Exception as e:
        results["details"].append(f"Binwalk analysis failed or not installed: {str(e)}")

    # 2. zsteg (Specifically for PNG/BMP)
    if file_path.lower().endswith('.png') or file_path.lower().endswith('.bmp'):
        try:
            zs_process = subprocess.run([zsteg_cmd, file_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            results["tools_used"].append("zsteg")
            if zs_process.returncode == 0 and zs_process.stdout:
                output = zs_process.stdout
                # zsteg prints findings. If there's meaningful output, it found something.
                if ".." in output or "file:" in output:
                    results["payload_extracted"] = True
                    results["details"].append("zsteg detected hidden data (LSB/extradata).")
                    results["risk_score_contribution"] += 25
        except Exception as e:
            results["details"].append(f"zsteg analysis failed or not installed: {str(e)}")

    return results
