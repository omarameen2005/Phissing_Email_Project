# engine/model_loader.py
"""
Singleton Model Loader
Loads the trained phishing detection model once at startup and keeps it in memory.
Thread-safe, fault-tolerant, and supports hot-swapping in the future.
"""
import joblib
import os
import threading
from typing import Optional, Any
from pathlib import Path

# ------------------------------------------------------------------
# Configuration
# ------------------------------------------------------------------
MODEL_DIR = Path("model")
MODEL_PATH = MODEL_DIR / "phishing_model_full.pkl"
FALLBACK_MODEL_PATH = MODEL_DIR / "phishing_model.pkl"  # Optional legacy fallback

# ------------------------------------------------------------------
# Global model instance + thread lock
# ------------------------------------------------------------------
_model: Optional[Any] = None
_model_lock = threading.Lock()  # Ensures thread-safe loading


# ------------------------------------------------------------------
# Public API
# ------------------------------------------------------------------
def load_model() -> Any:
    """
    Load the ML model from disk.
    Called once at startup via app factory.
    Raises detailed exceptions if model is missing or corrupted.
    """
    global _model

    if _model is not None:
        return _model  # Already loaded

    with _model_lock:
        if _model is not None:
            return _model

        if not MODEL_PATH.exists():
            # Try fallback model (for backward compatibility)
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

            # Basic sanity check
            if not hasattr(_model, "predict_proba"):
                raise ValueError("Loaded object is not a valid scikit-learn model (missing predict_proba)")

            print(f"[Success] Model loaded successfully → {type(_model).__name__}")
            return _model

        except Exception as e:
            print(f"[ERROR] Failed to load model: {e}")
            raise RuntimeError(f"Could not load phishing model from {model_file}") from e


def get_model() -> Any:
    """
    Return the loaded model.
    Automatically loads it on first call (lazy fallback).
    Never returns None in production.
    """
    global _model
    if _model is None:
        with _model_lock:
            if _model is None:
                return load_model()
    return _model


def is_model_loaded() -> bool:
    """Check if model is currently loaded (useful for health checks)."""
    return _model is not None


def reload_model() -> bool:
    """
    Force reload model from disk (e.g., after retraining).
    Returns True on success.
    """
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


# ------------------------------------------------------------------
# Optional: Auto-load on import (safe if called multiple times)
# ------------------------------------------------------------------
if os.getenv("PHISHING_SHIELD_EAGER_LOAD", "1") == "1":
    try:
        load_model()
    except Exception as e:
        # Don't crash import — let app factory handle it
        print(f"[WARNING] Model pre-load failed (will retry later): {e}")