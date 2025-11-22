from flask import Blueprint, render_template, request, jsonify
from datetime import datetime
from engine.processor import process_email

main = Blueprint("main", __name__)
logs = []


@main.route("/", methods=["GET", "POST"])
def index():
    global logs

    if request.method == "POST":
        email_text = request.form.get("email", "").strip()

        if email_text:
            result = process_email(email_text=email_text)

            logs.append({
                "id": len(logs) + 1,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "label": result["label"],
                "confidence": result.get("confidence"),
                "reason": result["reason"]
            })

    # Calculate stats
    stats = {
        "total": len(logs),
        "Phishing": sum(1 for log in logs if log["label"] == "Phishing"),
        "Suspicious": sum(1 for log in logs if log["label"] == "Suspicious"),
        "Safe": sum(1 for log in logs if log["label"] == "Safe")
    }

    return render_template(
        "index.html",
        logs=logs[-20:],  # Show only last 20
        stats=stats,
        datetime=datetime
    )


@main.route("/scan", methods=["GET", "POST"])
def scan_page():
    global logs

    if request.method == "POST":
        email_text = request.form.get("email", "").strip()

        if email_text:
            result = process_email(email_text=email_text)

            logs.append({
                "id": len(logs) + 1,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "label": result["label"],
                "confidence": result.get("confidence"),
                "reason": result["reason"]
            })

            return render_template("scan.html", result=result)

    return render_template("scan.html")


@main.route("/scan_api", methods=["POST"])
def scan_api():
    global logs
    data = request.get_json() or {}
    email_text = data.get("email_text", "").strip()

    if not email_text:
        return jsonify({"error": "No email provided"}), 400

    result = process_email(
        email_text=email_text,
        ip_address=request.remote_addr or "unknown",
        user_agent=request.headers.get("User-Agent", "unknown")
    )

    
    logs.append({
        "id": len(logs) + 1,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "label": result["label"],
        "confidence": result.get("confidence"),
        "reason": result["reason"]
    })

    return jsonify({
        "label": result["label"],
        "confidence": result.get("confidence"),
        "reason": result["reason"]
    })


@main.route("/logs")
def logs_page():
    stats = {
        "total": len(logs),
        "Phishing": sum(1 for log in logs if log["label"] == "Phishing"),
        "Suspicious": sum(1 for log in logs if log["label"] == "Suspicious"),
        "Safe": sum(1 for log in logs if log["label"] == "Safe")
    }

    return render_template("logs.html", logs=logs[::-1], stats=stats)  # Newest first