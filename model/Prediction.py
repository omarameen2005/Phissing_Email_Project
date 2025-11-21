import re
import numpy as np
import joblib
import sys

def predict_email(text, thresholds=(0.7, 0.3)):
   
    try:
        if not text or not isinstance(text, str):
            return None, None
        
        model = joblib.load("phishing_model_full.pkl")
        proba = model.predict_proba([text])[0]
        phish_prob = proba[1] 
        
        if phish_prob >= thresholds[0]:  
            return "Phishing", phish_prob
        elif phish_prob <= thresholds[1]:  
            return "Safe", phish_prob
        else:
            return "Suspicious", phish_prob
    except Exception as e:
        print(f"Error in prediction: {e}", file=sys.stderr)
        return None, None

if __name__ == "__main__":
    sample_text = """  """
    
    label, prob = predict_email(sample_text)
    if label is not None:
        print(f"Prediction: {label} (Phishing probability: {prob:.2f})")
    else:
        print("Prediction failed.")