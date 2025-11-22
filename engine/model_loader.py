import joblib
import os
import threading
from typing import Optional, Any
from pathlib import Path

MODEL_DIR = Path("model")
MODEL_PATH = MODEL_DIR / "phishing_model_full.pkl"
FALLBACK_MODEL_PATH = MODEL_DIR / "phishing_model.pkl" 

_model: Optional[Any] = None
_model_lock = threading.Lock()  


def load_model() -> Any:

    global _model

    if _model is not None:
        return _model  

    with _model_lock:
        if _model is not None:
            return _model

        if not MODEL_PATH.exists():
            if FALLBACK_MODEL_PATH.exists():
                print(f"[WARNING] Main model not found, using fallback: {FALLBACK_MODEL_PATH}")
                model_file = FALLBACK_MODEL_PATH
            else:
                raise FileNotFoundError(
                    f"Phishing model not found!\n"
                    f"Expected: {MODEL_PATH}\n"
                    f"Checked directory: {MODEL_DIR.resolve()}\n"
                    f"Tip: Run python model/train_model.py to generate it."
                )
        else:
            model_file = MODEL_PATH

        try:
            print(f"[+] Loading phishing detection model from: {model_file}")
            _model = joblib.load(model_file)


            if not hasattr(_model, "predict_proba"):
                raise ValueError("Loaded object is not a valid scikit-learn model (missing predict_proba)")

            print(f"[Success] Model loaded successfully → {type(_model).__name__}")
            return _model

        except Exception as e:
            print(f"[ERROR] Failed to load model: {e}")
            raise RuntimeError(f"Could not load phishing model from {model_file}") from e


def get_model() -> Any:

    global _model
    if _model is None:
        with _model_lock:
            if _model is None:
                return load_model()
    return _model


def is_model_loaded() -> bool:
    return _model is not None


def reload_model() -> bool:
    global _model
    try:
        with _model_lock:
            _model = None
            load_model()
        print("[Success] Model reloaded successfully.")
        return True
    except Exception as e:
        print(f"[ERROR] Failed to reload model: {e}")
        return False


if os.getenv("PHISHING_SHIELD_EAGER_LOAD", "1") == "1":
    try:
        load_model()
    except Exception as e:
        print(f"[WARNING] Model pre-load failed (will retry later): {e}")