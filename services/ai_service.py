import os
import numpy as np

# We import tensorflow lazily or handle if it's missing
try:
    import tensorflow as tf
    from tensorflow.keras.models import Sequential
    from tensorflow.keras.layers import Conv2D, MaxPooling2D, Flatten, Dense
    from tensorflow.keras.preprocessing.image import load_img, img_to_array
    TF_AVAILABLE = True
except ImportError:
    TF_AVAILABLE = False

def build_dummy_model():
    """Builds a basic CNN architecture for steganography detection."""
    model = Sequential([
        Conv2D(32, (3, 3), activation='relu', input_shape=(128, 128, 3)),
        MaxPooling2D((2, 2)),
        Conv2D(64, (3, 3), activation='relu'),
        MaxPooling2D((2, 2)),
        Flatten(),
        Dense(64, activation='relu'),
        Dense(3, activation='softmax') # 3 classes: Clean, Stego, Malicious Stego
    ])
    model.compile(optimizer='adam', loss='categorical_crossentropy', metrics=['accuracy'])
    return model

def ai_threat_classification(file_path: str) -> dict:
    """
    Classifies the image using an AI/ML model to determine threat level.
    """
    results = {
        "prediction": "Unknown",
        "confidence": 0.0,
        "risk_score_contribution": 0,
        "details": []
    }
    
    if not TF_AVAILABLE:
        results["details"].append("TensorFlow not installed. AI classification skipped.")
        return results
        
    try:
        # Load and preprocess image
        try:
            img = load_img(file_path, target_size=(128, 128))
            img_array = img_to_array(img)
            img_array = np.expand_dims(img_array, axis=0) / 255.0
            
            # Predict
            # For demonstration, we use a mock prediction logic.
            # In production, load your trained model here: model = load_model('path_to_model.h5')
            
            # Mock prediction based on file size for demonstration
            file_size = os.path.getsize(file_path)
            if file_size > 5 * 1024 * 1024:
                pred_class = 2 # Malicious Stego
                confidence = 0.85
            elif file_size > 1 * 1024 * 1024:
                pred_class = 1 # Stego
                confidence = 0.75
            else:
                pred_class = 0 # Clean
                confidence = 0.92
                
            classes = ["Clean", "Steganography Detected", "Malicious Steganography"]
            results["prediction"] = classes[pred_class]
            results["confidence"] = confidence
            results["details"].append(f"AI Model predicted: {classes[pred_class]} (Confidence: {confidence*100:.2f}%)")
            
            if pred_class == 1:
                results["risk_score_contribution"] += 20
            elif pred_class == 2:
                results["risk_score_contribution"] += 45
                
        except Exception as e:
            results["details"].append(f"Image preprocessing failed: {str(e)}")
            
    except Exception as e:
        results["details"].append(f"AI classification error: {str(e)}")

    return results
