# engine/chain.py
"""
Chain of Responsibility - Hybrid Phishing Detection
Combines rule-based (URL + Header) and ML analysis in a clean, extensible pipeline.
Returns consistent dict results for processor.py and logging.
"""
import re
import email
from email.utils import parseaddr
from typing import Optional, Dict, Any
from .extractor_url import url_features
from .model_loader import get_model


class BaseHandler:
    """Base class for all handlers in the chain."""
    def __init__(self, successor: 'BaseHandler' = None):
        self.successor = successor

    def handle(self, email_text: str) -> Optional[Dict[str, Any]]:
        """
        Process the email. Return a result dict if decision made,
        otherwise delegate to successor.
        """
        raise NotImplementedError("Subclasses must implement handle()")


# ────────────────────────────── URL Handler ──────────────────────────────
class URLHandler(BaseHandler):
    """Detects phishing via suspicious URLs using weighted risk scoring."""
    
    THRESHOLDS = {
        'length': 70,
        'dots': 4,
        'specials': 5
    }

    def handle(self, email_text: str) -> Optional[Dict[str, Any]]:
        feats = url_features(email_text)
        length, dots, at_sym, no_https, keywords, ip, tld, shortener, specials, uppercase = feats

        # Weighted risk scoring (tuned for high precision)
        risk = 0.0
        risk += (length > self.THRESHOLDS['length']) * 0.28
        risk += (dots > self.THRESHOLDS['dots']) * 0.22
        risk += keywords * 0.38
        risk += ip * 0.65
        risk += tld * 0.48
        risk += shortener * 0.50
        risk += (specials > self.THRESHOLDS['specials']) * 0.24
        risk += no_https * 0.18
        risk += uppercase * 0.15

        if risk > 0.58:
            return {
                "label": "Phishing",
                "confidence": min(risk, 0.99),
                "reason": f"Highly suspicious URL detected (risk score: {risk:.3f})"
            }

        # Low-risk URLs still pass to next handler
        return self.successor.handle(email_text) if self.successor else None


# ────────────────────────────── Header Handler ──────────────────────────────
class HeaderHandler(BaseHandler):
    """Analyzes email headers for spoofing, impersonation, and anomalies."""
    
    BAD_TLDS = re.compile(
        r"\.(ru|cn|tk|top|xyz|zip|biz|pw|info|ga|gq|ml|cf|sbs|pub|cfd|so|icu|re|ua|online|link|ly|site|click)$",
        re.IGNORECASE
    )

    BRAND_IMPERSONATION = {
        "paypal": ["paypa1", "paypal-secure", "paypal-update", "pavpal"],
        "amazon": ["amaz0n", "amazon-secure", "amazon-verify"],
        "google": ["gooogle", "g00gle", "google-security", "googl-e"],
        "microsoft": ["micr0soft", "microsoft-secure", "outlook-verify", "m1crosoft"],
        "apple": ["app1e", "apple-support", "icloud-security", "appl-e"],
        "netflix": ["netf1ix", "netflix-support"],
        "bankofamerica": ["bank0famerica", "bofa-secure"]
    }

    def handle(self, email_text: str) -> Optional[Dict[str, Any]]:
        try:
            msg = email.message_from_string(email_text)
            sender = msg.get("From", "").strip()

            if not sender:
                return {"label": "Phishing", "confidence": 0.94, "reason": "Missing From header"}

            # Extract clean email address
            _, addr = parseaddr(sender)
            if not addr:
                return {"label": "Phishing", "confidence": 0.91, "reason": "Invalid or missing sender address"}

            addr = addr.lower()
            domain = addr.split("@")[-1] if "@" in addr else ""

            # Basic format validation
            if not re.match(r"^[^@]+@[^@]+\.[^@]+$", addr):
                return {"label": "Phishing", "confidence": 0.89, "reason": f"Malformed email address: {addr}"}

            # Suspicious TLD
            if self.BAD_TLDS.search(domain):
                return {"label": "Phishing", "confidence": 0.90, "reason": f"Suspicious domain TLD: {domain}"}

            # Brand impersonation detection
            domain_lower = domain.lower()
            for brand, patterns in self.BRAND_IMPERSONATION.items():
                if brand in domain_lower:
                    if not domain_lower.endswith(f"{brand}.com"):
                        return {
                            "label": "Phishing",
                            "confidence": 0.97,
                            "reason": f"Brand impersonation detected: {domain} (spoofing {brand}.com)"
                        }
                for pattern in patterns:
                    if pattern in domain_lower:
                        return {
                            "label": "Phishing",
                            "confidence": 0.98,
                            "reason": f"Known phishing pattern in domain: {pattern} → {domain}"
                        }

            # Nested or obfuscated sender
            if re.search(r"@[a-zA-Z0-9-]+\.[a-zA-Z0-9-]+\.[a-zA-Z0-9-]+", sender):
                return {"label": "Phishing", "confidence": 0.87, "reason": "Nested/obfuscated domain in sender"}

            return self.successor.handle(email_text) if self.successor else None

        except Exception as e:
            # Never crash the chain
            print(f"[HeaderHandler] Exception: {e}")
            return self.successor.handle(email_text) if self.successor else None


# ────────────────────────────── ML Model Handler ──────────────────────────────
class ModelHandler(BaseHandler):
    """Final fallback: uses trained ML model for content-based prediction."""
    
    def handle(self, email_text: str) -> Dict[str, Any]:
        try:
            model = get_model()
            proba = model.predict_proba([email_text])[0]
            phish_prob = proba[1]

            if phish_prob >= 0.78:
                return {
                    "label": "Phishing",
                    "confidence": round(phish_prob, 4),
                    "reason": f"ML Model strongly indicates phishing ({phish_prob:.1%})"
                }
            elif phish_prob <= 0.22:
                return {
                    "label": "Safe",
                    "confidence": round(1 - phish_prob, 4),
                    "reason": "ML Model indicates legitimate email"
                }
            else:
                return {
                    "label": "Suspicious",
                    "confidence": round(phish_prob, 4),
                    "reason": f"ML Model uncertain ({phish_prob:.1%} phishing probability)"
                }
        except Exception as e:
            print(f"[ModelHandler] Error: {e}")
            return {"label": "Safe", "confidence": 0.0, "reason": "ML model unavailable"}


# ────────────────────────────── Chain Builder ──────────────────────────────
def build_chain() -> BaseHandler:
    """
    Constructs the detection chain:
    URL → Header → ML Model
    First match wins (early exit on high-confidence phishing)
    """
    model_handler = ModelHandler()
    header_handler = HeaderHandler(successor=model_handler)
    url_handler = URLHandler(successor=header_handler)
    return url_handler