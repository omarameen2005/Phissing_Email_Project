from typing import Dict, Any, Optional
import uuid
import traceback
from .chain import build_chain
from .logger import log_scan


def process_email(
    email_text: str,
    request_id: Optional[str] = None,
    ip_address: str = "unknown",
    user_agent: str = "unknown"
) -> Dict[str, Any]:

    if not email_text or not email_text.strip():
        result = {
            "label": "Error",
            "confidence": 0.0,
            "reason": "Empty or invalid email content",
            "request_id": request_id or str(uuid.uuid4()),
            "quarantined": False
        }
        log_scan(email_text="", label="Error", reason=result["reason"])
        return result

    if len(email_text) > 500_000: 
        result = {
            "label": "Error",
            "confidence": 0.0,
            "reason": "Email too large (>500KB)",
            "request_id": request_id or str(uuid.uuid4()),
            "quarantined": False
        }
        log_scan(email_text="[TOO LARGE]", label="Error", reason=result["reason"])
        return result

    try:
        chain = build_chain()
        raw_result = chain.handle(email_text.strip())

        if raw_result is None:
            raw_result = {
                "label": "Safe",
                "confidence": 0.95,
                "reason": "No phishing indicators detected"
            }

    except Exception as e:
        traceback.print_exc()
        raw_result = {
            "label": "Error",
            "confidence": 0.0,
            "reason": f"Detection engine failure: {str(e)}"
        }


    label = str(raw_result.get("label", "Unknown")).strip()
    confidence = float(raw_result.get("confidence", 0.0))
    reason = str(raw_result.get("reason", "No reason provided")).strip()

    valid_labels = {"Phishing", "Suspicious", "Safe", "Error"}
    if label not in valid_labels:
        label = "Safe"
        reason = f"Invalid label corrected: {raw_result.get('label')} → Safe"

    confidence = max(0.0, min(1.0, confidence))
    req_id = request_id or str(uuid.uuid4())

    result = {
        "label": label,
        "confidence": round(confidence, 4),
        "reason": reason,
        "request_id": req_id,
        "quarantined": False,
        "timestamp": None  
    }

    log_scan(
        email_text=email_text,
        label=label,
        confidence=confidence if confidence > 0 else None,
        reason=reason,
        ip_address=ip_address,
        user_agent=user_agent
    )

    return result