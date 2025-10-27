#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CIS Aurora — Local HTTP Server
- POST /analyze (form 'address')
- GET  / (UI)
- GET  /health
- GET  /last-report
- GET  /last-report-html (ładna nakładka HTML)
"""
from flask import Flask, request, jsonify, send_from_directory
import subprocess, os, time, re, glob, sys

# ------------------- APP CONFIG -------------------
APP_ROOT = os.path.dirname(os.path.abspath(__file__))
ANALYZE_DIR = os.path.join(APP_ROOT, "ANALYZE")
LOGS_DIR = os.path.join(APP_ROOT, "LOGS")
ANALYZER_CMD = "python anty_scam.py {address}"
ANALYZE_TIMEOUT_SEC = 180
ADDRESS_RE = re.compile(r"^0x[a-fA-F0-9]{40}$")

app = Flask(__name__, static_folder="assets", static_url_path="/assets")

# ------------------- UTILS -------------------
def tail_text(txt: str, max_len: int = 2000) -> str:
    if len(txt) <= max_len:
        return txt
    return txt[-max_len:]

def latest_report_path() -> str:
    """Return newest file path in ANALYZE subfolders."""
    files = []
    for sub in ["GOOD", "RISK", "EXTREME_RISK"]:
        files.extend(glob.glob(os.path.join(ANALYZE_DIR, sub, "*.txt")))
        files.extend(glob.glob(os.path.join(ANALYZE_DIR, sub, "*.json")))
    if not files:
        return ""
    files.sort(key=os.path.getmtime, reverse=True)
    return files[0]

# ------------------- ROUTES -------------------
@app.route("/")
def home():
    return open(os.path.join(APP_ROOT, "index.html"), "r", encoding="utf-8").read()

@app.route("/health")
def health():
    return jsonify({"status": "ok", "time": int(time.time())})

@app.route("/last-report")
def last_report():
    path = latest_report_path()
    if not path:
        return jsonify({"error": "No reports yet"}), 404
    try:
        ext = os.path.splitext(path)[1].lower()
        content = open(path, "r", encoding="utf-8", errors="ignore").read()
        return jsonify({
            "path": os.path.relpath(path, APP_ROOT),
            "ext": ext,
            "content": tail_text(content, 5000)
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/analyze", methods=["POST"])
def analyze():
    address = (request.form.get("address") or "").strip()
    if not ADDRESS_RE.match(address):
        return jsonify({"error": "Invalid ETH address. Expected 0x + 40 hex chars."}), 400

    cmd = ANALYZER_CMD.format(address=address)
    start_ts = time.time()
    try:
        proc = subprocess.run(
            cmd,
            cwd=APP_ROOT,
            shell=True,
            capture_output=True,
            text=True,
            timeout=ANALYZE_TIMEOUT_SEC
        )
        elapsed = round(time.time() - start_ts, 2)
        status = "ok" if proc.returncode == 0 else "error"
        return jsonify({
            "status": status,
            "elapsed_sec": elapsed,
            "address": address,
            "cmd": cmd,
            "stdout_tail": tail_text(proc.stdout, 4000),
            "stderr_tail": tail_text(proc.stderr, 2000),
            "last_report": os.path.relpath(latest_report_path(), APP_ROOT) if latest_report_path() else None
        }), (200 if status == "ok" else 500)
    except subprocess.TimeoutExpired:
        return jsonify({"error": f"Analyzer timed out after {ANALYZE_TIMEOUT_SEC}s", "address": address}), 504

@app.route("/assets/<path:filename>")
def assets(filename):
    return send_from_directory(os.path.join(APP_ROOT, "assets"), filename)

# ------------------- HTML OVERLAY -------------------
def _parse_first_line_csv(txt: str):
    for ln in txt.splitlines():
        s = ln.strip()
        if not s:
            continue
        parts = [p.strip() for p in s.split(",")]
        if len(parts) >= 4 and ADDRESS_RE.match(parts[1]):
            return {
                "name": parts[0],
                "address": parts[1],
                "score": parts[2],
                "label": parts[3],
            }
        break
    return None

@app.route("/last-report-html")
def last_report_html():
    """Ładna wizualizacja ostatniego raportu (HTML panel)."""
    path = latest_report_path()
    if not path:
        return "<p>Brak raportów.</p>", 404, {"Content-Type": "text/html; charset=utf-8"}
    try:
        txt = open(path, "r", encoding="utf-8", errors="ignore").read()
        item = _parse_first_line_csv(txt) or {"name": "?", "address": "?", "score": "?", "label": "?"}
        name = item.get("name", "?")
        addr = item.get("address", "?")
        score = item.get("score", "?")
        label = item.get("label", "?")

        # Przygotowanie badge
        label_up = (label or "").upper()
        if "GOOD" in label_up:
            badge = "<span style='padding:4px 10px;border-radius:999px;font-weight:bold;background:#1c8f4d;color:#fff'>GOOD</span>"
        elif "EXTREME" in label_up:
            badge = "<span style='padding:4px 10px;border-radius:999px;font-weight:bold;background:#d62828;color:#fff'>EXTREME RISK</span>"
        else:
            badge = "<span style='padding:4px 10px;border-radius:999px;font-weight:bold;background:#ffb703;color:#111'>RISK</span>"

        # HTML panel wyników
        html = f"""
        <div style='border:1px solid #444;border-radius:12px;padding:16px;margin-bottom:8px'>
          <div style='display:flex;gap:8px;align-items:center'>
            {badge}<div style='margin-left:8px'><b>{name}</b></div>
          </div>
          <div style='margin-top:8px;font-size:14px;line-height:1.4'>
            <div><strong>Adres:</strong> {addr}</div>
            <div><strong>Wynik:</strong> {score}</div>
            <div><strong>Plik:</strong> {os.path.relpath(path, APP_ROOT)}</div>
          </div>
        </div>
        """
        return html, 200, {"Content-Type": "text/html; charset=utf-8"}
    except Exception as e:
        return f"<pre>Błąd renderowania: {e}</pre>", 500, {"Content-Type": "text/html; charset=utf-8"}

# ------------------- MAIN -------------------
if __name__ == "__main__":
    # 0.0.0.0 = dostęp w sieci LAN; localhost-only → 127.0.0.1
    app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)
