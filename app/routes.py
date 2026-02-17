from flask import Blueprint, json, render_template, request, jsonify, abort  
from datetime import datetime
from engine.processor import process_email
from engine.logger import get_recent_logs, get_stats, get_conn  

main = Blueprint("main", __name__)

@main.route("/", methods=["GET", "POST"])
def index():
    stats = get_stats() 
    logs = get_recent_logs(20)  

    return render_template(
        "index.html",
        logs=logs,
        stats=stats,
        datetime=datetime  
    )

@main.route("/scan", methods=["GET", "POST"])
def scan_page():
    if request.method == "POST":
        email_text = request.form.get("email", "").strip()
        if email_text:
            result = process_email(email_text=email_text)
            return render_template("scan.html", result=result)

    return render_template("scan.html")

@main.route("/scan_api", methods=["POST"])
def scan_api():
    data = request.get_json() or {}
    email_text = data.get("email_text", "").strip()

    if not email_text:
        return jsonify({"error": "No email provided"}), 400

    result = process_email(
        email_text=email_text,
        ip_address=request.remote_addr or "unknown",
        user_agent=request.headers.get("User-Agent", "unknown")
    )

    return jsonify({
        "label": result["label"],
        "confidence": result.get("confidence"),
        "reason": result["reason"]
    })

@main.route("/logs")
def logs_page():
    stats = get_stats()  
    logs = get_recent_logs(1000) 

    return render_template("logs.html", logs=logs, stats=stats) 

@main.route("/detail/<int:log_id>")
def detail(log_id):
    conn = get_conn()
    log = conn.execute("SELECT * FROM email_logs WHERE id=?", (log_id,)).fetchone()
    if not log:
        abort(404)
    return render_template("detail.html", log=dict(log))



@main.route("/shap/<int:log_id>")
def get_shap(log_id):
    conn = get_conn()
    row = conn.execute("SELECT shap_data FROM email_logs WHERE id=?", (log_id,)).fetchone()
    if not row or not row['shap_data']:
        return jsonify({"error": "No SHAP data"}), 404
    return jsonify(json.loads(row['shap_data']))