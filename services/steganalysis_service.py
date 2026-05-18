import cv2
import numpy as np

def analyze_image_statistics(file_path: str) -> dict:
    """
    Analyzes image statistical properties using OpenCV to detect potential LSB steganography.
    """
    results = {
        "histogram_anomaly": False,
        "lsb_inconsistency": False,
        "risk_score_contribution": 0,
        "details": []
    }
    
    try:
        # Load image in grayscale for simple analysis
        img = cv2.imread(file_path, cv2.IMREAD_GRAYSCALE)
        if img is None:
            results["details"].append("Could not load image for OpenCV analysis.")
            return results
            
        # 1. Histogram Anomaly Detection
        # In LSB stego, histogram pairs (0,1), (2,3), etc., tend to equalize.
        hist = cv2.calcHist([img], [0], None, [256], [0, 256]).flatten()
        
        # Calculate pair differences (Chi-square attack concept)
        diff_sum = 0
        for i in range(0, 255, 2):
            avg = (hist[i] + hist[i+1]) / 2.0
            if avg > 0:
                diff_sum += ((hist[i] - avg)**2 + (hist[i+1] - avg)**2) / avg
                
        # threshold is empirical; lower diff_sum = more uniform pairs = likely LSB stego
        if diff_sum > 0 and diff_sum < 10000: # Placeholder threshold
            results["histogram_anomaly"] = True
            results["details"].append("Histogram pair analysis indicates potential LSB manipulation.")
            results["risk_score_contribution"] += 15

        # 2. LSB Inconsistency (Simple check: variance of LSB plane)
        lsb_plane = img & 1
        lsb_variance = np.var(lsb_plane)
        
        # Normal images have structured LSBs to some extent. High variance = closer to random
        if lsb_variance > 0.245: # Max variance is 0.25 (perfectly random)
            results["lsb_inconsistency"] = True
            results["details"].append(f"High LSB variance ({lsb_variance:.4f}) detected, suggesting encrypted payload.")
            results["risk_score_contribution"] += 15

    except Exception as e:
        results["details"].append(f"OpenCV analysis error: {str(e)}")

    return results
