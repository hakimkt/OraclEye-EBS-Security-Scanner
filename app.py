"""
Oracle EBS Security Scanner - Main Flask Application
"""

from flask import Flask, render_template, request, jsonify, Response
import json
import threading
import uuid
import time
from datetime import datetime
from scanner.engine import ScanEngine
from scanner.registry import PluginRegistry

app = Flask(__name__)
app.secret_key = "oracle-ebs-scanner-2024"

# In-memory scan job store
scan_jobs = {}

@app.route("/")
def index():
    registry = PluginRegistry()
    plugins = registry.list_plugins()
    return render_template("index.html", plugins=plugins)

@app.route("/api/scan/start", methods=["POST"])
def start_scan():
    data = request.json
    target = data.get("target", "").strip()
    intrusivity = data.get("intrusivity", "passive")
    selected_modules = data.get("modules", [])
    options = data.get("options", {})

    if not target:
        return jsonify({"error": "Target URL is required"}), 400

    job_id = str(uuid.uuid4())
    scan_jobs[job_id] = {
        "id": job_id,
        "target": target,
        "intrusivity": intrusivity,
        "status": "running",
        "started_at": datetime.now().isoformat(),
        "findings": [],
        "log": [],
        "stats": {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
        "progress": 0,
    }

    def run_scan():
        engine = ScanEngine(
            target=target,
            intrusivity=intrusivity,
            modules=selected_modules,
            options=options,
            job=scan_jobs[job_id],
        )
        engine.run()
        scan_jobs[job_id]["status"] = "complete"
        scan_jobs[job_id]["completed_at"] = datetime.now().isoformat()

    t = threading.Thread(target=run_scan, daemon=True)
    t.start()

    return jsonify({"job_id": job_id})

@app.route("/api/scan/<job_id>/status")
def scan_status(job_id):
    job = scan_jobs.get(job_id)
    if not job:
        return jsonify({"error": "Job not found"}), 404
    return jsonify(job)

@app.route("/api/scan/<job_id>/stream")
def scan_stream(job_id):
    """Server-Sent Events stream for live scan updates."""
    def generate():
        last_log_idx = 0
        last_finding_idx = 0
        while True:
            job = scan_jobs.get(job_id)
            if not job:
                yield f"data: {json.dumps({'error': 'Job not found'})}\n\n"
                break

            new_logs = job["log"][last_log_idx:]
            new_findings = job["findings"][last_finding_idx:]

            if new_logs or new_findings or job["status"] in ("complete", "error"):
                payload = {
                    "status": job["status"],
                    "progress": job["progress"],
                    "stats": job["stats"],
                    "new_logs": new_logs,
                    "new_findings": new_findings,
                }
                yield f"data: {json.dumps(payload)}\n\n"
                last_log_idx += len(new_logs)
                last_finding_idx += len(new_findings)

            if job["status"] in ("complete", "error"):
                break

            time.sleep(0.5)

    return Response(generate(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

@app.route("/api/scan/<job_id>/report")
def scan_report(job_id):
    job = scan_jobs.get(job_id)
    if not job:
        return jsonify({"error": "Job not found"}), 404
    return jsonify(job)

@app.route("/api/plugins")
def list_plugins():
    registry = PluginRegistry()
    return jsonify(registry.list_plugins())

@app.route("/api/scans")
def list_scans():
    return jsonify([
        {k: v for k, v in job.items() if k != "log"}
        for job in scan_jobs.values()
    ])

if __name__ == "__main__":
    app.run(debug=True, threaded=True, port=5000)

import os

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
