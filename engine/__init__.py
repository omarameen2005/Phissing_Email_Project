# engine/__init__.py
"""
Phishing Shield Engine - Core Detection System
A modular, high-performance phishing detection engine with:
- Chain of Responsibility pattern
- ML + Rule-based hybrid detection
- Persistent logging & quarantine
- Singleton model loading
"""

# ------------------------------------------------------------------
# Core Processing & Chain
# ------------------------------------------------------------------
from .chain import (
    BaseHandler,
    URLHandler,
    HeaderHandler,
    ModelHandler,
    build_chain
)


# ------------------------------------------------------------------
# Logging System (SQLite)
# ------------------------------------------------------------------
from .logger import (
    init_db,
    log_scan,
    get_recent_logs,
    get_stats,
    get_conn
)


# ------------------------------------------------------------------
# URL Feature Extractor
# ------------------------------------------------------------------
from .extractor_url import (
    extract_urls,
    url_features
)

# ------------------------------------------------------------------
# Model Management (Singleton)
# ------------------------------------------------------------------
from .model_loader import (
    load_model,
    get_model
)

# ------------------------------------------------------------------
# Optional: Expose version
# ------------------------------------------------------------------
__version__ = "1.0.0"
__author__ = "Your Name"

# ------------------------------------------------------------------
# Convenience: Auto-initialize on import (optional but useful)
# ------------------------------------------------------------------
# This ensures DB is ready even if someone imports engine directly
try:
    init_db()
except Exception:
    pass  # Fail silently if called multiple times

__all__ = [
    # Chain
    "BaseHandler", "URLHandler", "HeaderHandler", "ModelHandler", "build_chain",
    # Core
    "process_email",
    # Logging
    "init_db", "log_scan", "get_recent_logs", "get_stats",
    # Quarantine
    "quarantine_email", "get_quarantined_files",
    # Utils
    "extract_urls", "url_features",
    # Model
    "load_model", "get_model"
]