#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CIS Aurora — Local HTTP Server
- POST /analyze (form 'address')
- GET  / (UI)
- GET  /health
- GET  /last-report
- GET  /last-report-html (ładna nakładka HTML z 'oczami')
"""
from flask import Flask, request, jsonify, send_from_directory
import subprocess, os, time, re, glob, sys, json

# ------------------- APP CONFIG -------------------
APP_ROOT = os.path.dirname(os.path.abspath(__file__))
ANALYZE_DIR = os.path.join(APP_ROOT, "ANALYZE")
LOGS_DIR = os.path.join(APP_ROOT, "LOGS")
ANALYZER_CMD = "python anty_scam.py {address}"
ANALYZE_TIMEOUT_SEC = 180
ADDRESS_RE = re.compile(r"^0x[a-fA-F0-9]{40}$")

app = Flask(__name__, static_folder="assets", static_url_path="/assets")

# ------------------- EYES (ikonki + opisówki) -------------------
EYES_PATH = os.path.join(APP_ROOT, "eyes.json")
EYES_DATA = {}
EYES_ORDER = []

def _load_eyes():
    global EYES_DATA, EYES_ORDER
    try:
        with open(EYES_PATH, "r", encoding="utf-8") as f:
            arr = json.load(f)
        # zachowaj kolejność z pliku
        EYES_DATA = {e["key"]: e for e in arr}
        EYES_ORDER = [e["key"] for e in arr]
        print(f"[EYES] Loaded {len(EYES_ORDER)} items from eyes.json")
    except Exception as e:
        EYES_DATA, EYES_ORDER = {}, []
        print(f"[EYES][WARN] Could not load eyes.json: {e}")

_load_eyes()

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

def _badge_by_score(sc: float) -> str:
    if sc >= 8:
        return "<span style='padding:6px 12px;border-radius:999px;background:#1c8f4d;color:#fff;font-weight:700'>GOOD</span>"
    if sc >= 5:
        return "<span style='padding:6px 12px;border-radius:999px;background:#ffb703;color:#111;font-weight:700'>RISK</span>"
    return "<span style='padding:6px 12px;border-radius:999px;background:#d62828;color:#fff;font-weight:700'>EXTREME</span>"

# ------------------- MAPPING RULES -------------------
MAP_RULES = [
    ("honeypot", "honeypot"),
    ("podatk", "high_tax"),
    ("fee", "high_tax"),
    ("dodruk", "mint_unlimited"),
    ("mint", "mint_unlimited"),
    ("100%", "constructor_mint_msgsender"),
    ("owner", "constructor_mint_msgsender"),
    ("blacklist", "blacklist_trading"),
    ("pauz", "pause_control"),
    ("withdraw", "withdraw_stuck"),
    ("kill", "kill_switch_v2"),
    ("proxy", "proxy_like"),
    ("router", "router_exception"),
    ("obfusk", "assembly_obfuscation"),
    ("dynamic", "dynamic_fee"),
    ("reflection", "reflection_tax"),
    ("liquidity", "liquidity_removable"),
]

def _normalize_detected_from_json(report: dict) -> list:
    out, candidates = [], []
    for key in ["threats", "flags", "issues", "detections"]:
        v = report.get(key)
        if not v:
            continue
        if isinstance(v, list):
            candidates.extend([str(x) for x in v])
        elif isinstance(v, dict):
            for k, val in v.items():
                if val:
                    candidates.append(k)
    for s in candidates:
        s_l = s.strip().lower()
        if s_l in EYES_DATA and s_l not in out:
            out.append(s_l)
    for s in candidates:
        s_l = s.lower()
        for sub, tid in MAP_RULES:
            if sub in s_l and tid in EYES_DATA and tid not in out:
                out.append(tid)
    return out

@app.route("/last-report-html")
def last_report_html():
    path = latest_report_path()
    if not path:
        return "<p>Brak raportów.</p>", 404, {"Content-Type": "text/html; charset=utf-8"}
    try:
        rel = os.path.relpath(path, APP_ROOT)
        ext = os.path.splitext(path)[1].lower()

        # ===== JSON =====
        if ext == ".json":
            data = json.load(open(path, "r", encoding="utf-8", errors="ignore"))
            report = data[-1] if isinstance(data, list) and data else (data if isinstance(data, dict) else {})
            name = report.get("name") or report.get("identity", {}).get("resolved_name") or "Contract"
            addr = report.get("address", "?")
            try:
                score = float(report.get("score", 0.0))
            except Exception:
                score = 0.0

            badge = _badge_by_score(score)
            bar_w = max(0, min(100, int((score / 10.0) * 100)))
            detected_keys = _normalize_detected_from_json(report)

            # HEADER
            header = f"""
            <div style="padding:16px;margin-bottom:12px;background:#0f1114;border-radius:12px;
                        box-shadow:0 2px 12px rgba(0,0,0,.35)">
              <div style="display:flex;gap:12px;align-items:center;flex-wrap:wrap">
                {badge}
                <div style="font-weight:700;font-size:18px">{name}</div>
                <div style="margin-left:auto;color:#9aa0a6;font-size:12px">Plik: {rel}</div>
              </div>
              <div style="margin-top:8px;color:#cfd6dc">
                <div><small>Adres:</small> <code>{addr}</code></div>
                <div style="margin-top:6px"><small>Wynik:</small> {score:.2f} / 10</div>
                <div style="margin-top:8px">
                  <div style="height:8px;border-radius:999px;background:#222;overflow:hidden">
                    <span style="display:block;height:100%;width:{bar_w}%;background:linear-gradient(90deg,#3b82f6,#22c55e)"></span>
                  </div>
                </div>
              </div>
            </div>
            """

            # WYKRYTO
            items = []
            for tid in detected_keys:
                meta = EYES_DATA.get(tid, {})
                icon = meta.get("icon", "🔎")
                title = meta.get("label", tid)
                lines = meta.get("detected", [])
                text = " ".join(lines[:3])
                items.append(f"""
                  <div style="padding:14px;border-radius:12px;background:#16181f;
                              box-shadow:0 2px 10px rgba(0,0,0,.35)">
                    <div style="display:flex;gap:10px;align-items:flex-start">
                      <div style="font-size:22px">{icon}</div>
                      <div>
                        <div style="font-weight:700">{title}</div>
                        <div style="font-size:13px;line-height:1.55;opacity:.92;margin-top:4px">{text}</div>
                      </div>
                    </div>
                  </div>
                """)
            detected_html = (
                "<div style='margin-bottom:8px;font-weight:700;border-left:4px solid #d62828;padding-left:8px'>"
                "Wykryliśmy następujące zagrożenia</div>"
                f"<div style='display:grid;gap:12px'>{''.join(items)}</div>"
            )

            # CO ANALIZUJEMY
            pair_rows = []
            for i in range(0, len(EYES_ORDER), 2):
                pair = EYES_ORDER[i:i + 2]
                row = "<div style='display:flex;gap:20px;margin:20px 0 10px 0;flex-wrap:wrap'>"
                for tid in pair:
                    meta = EYES_DATA.get(tid, {})
                    icon = meta.get("icon", "🔎")
                    title = meta.get("label", tid)
                    lines = meta.get("analyze", [])
                    text = " ".join(lines[:4])
                    row += f"""
                      <div style="flex:1;min-width:280px;padding:14px;border-radius:12px;background:#0e1016;
                                  box-shadow:0 2px 10px rgba(0,0,0,.28)">
                        <div style="display:flex;gap:10px;align-items:flex-start">
                          <div style="font-size:22px">{icon}</div>
                          <div>
                            <div style="font-weight:700">{title}</div>
                            <div style="font-size:13px;line-height:1.55;opacity:.92;margin-top:4px">{text}</div>
                          </div>
                        </div>
                      </div>
                    """
                row += "</div>"
                pair_rows.append(row)
            analyze_html = (
                "<div style='margin-top:16px;margin-bottom:6px;font-weight:700;border-left:4px solid #3b82f6;padding-left:8px'>"
                "Co analizujemy (stałe obszary audytu)</div>"
                + "".join(pair_rows)
            )
            return header + detected_html + analyze_html, 200, {"Content-Type": "text/html; charset=utf-8"}

        # ===== TXT Fallback =====
        txt = open(path, "r", encoding="utf-8", errors="ignore").read()
        lower = txt.lower()
        detected_keys = [tid for sub, tid in MAP_RULES if sub in lower and tid in EYES_DATA]
        item = _parse_first_line_csv(txt) or {"name": "?", "address": "?", "score": "0", "label": "RISK"}
        name, addr = item.get("name", "?"), item.get("address", "?")
        score = float(item.get("score", 0.0)) if str(item.get("score", "")).replace(".", "", 1).isdigit() else 0.0
        badge = _badge_by_score(score)
        bar_w = max(0, min(100, int((score / 10.0) * 100)))

        # HEADER
        header = f"""
        <div style="padding:16px;margin-bottom:12px;background:#0f1114;border-radius:12px;
                    box-shadow:0 2px 12px rgba(0,0,0,.35)">
          <div style="display:flex;gap:12px;align-items:center;flex-wrap:wrap">
            {badge}
            <div style="font-weight:700;font-size:18px">{name}</div>
            <div style="margin-left:auto;color:#9aa0a6;font-size:12px">Plik: {os.path.relpath(path, APP_ROOT)}</div>
          </div>
          <div style="margin-top:8px;color:#cfd6dc">
            <div><small>Adres:</small> <code>{addr}</code></div>
            <div style="margin-top:6px"><small>Wynik:</small> {score:.2f} / 10</div>
            <div style="margin-top:8px">
              <div style="height:8px;border-radius:999px;background:#222;overflow:hidden">
                <span style="display:block;height:100%;width:{bar_w}%;background:linear-gradient(90deg,#3b82f6,#22c55e)"></span>
              </div>
            </div>
          </div>
        </div>
        """

        # WYKRYTO
        items = []
        for tid in detected_keys:
            meta = EYES_DATA.get(tid, {})
            icon = meta.get("icon", "🔎")
            title = meta.get("label", tid)
            lines = meta.get("detected", [])
            text = " ".join(lines[:3])
            items.append(f"""
              <div style="padding:14px;border-radius:12px;background:#16181f;
                          box-shadow:0 2px 10px rgba(0,0,0,.35)">
                <div style="display:flex;gap:10px;align-items:flex-start">
                  <div style="font-size:22px">{icon}</div>
                  <div>
                    <div style="font-weight:700">{title}</div>
                    <div style="font-size:13px;line-height:1.55;opacity:.92;margin-top:4px">{text}</div>
                  </div>
                </div>
              </div>
            """)
        detected_html = (
            "<div style='margin-bottom:8px;font-weight:700;border-left:4px solid #d62828;padding-left:8px'>"
            "Wykryliśmy następujące zagrożenia</div>"
            f"<div style='display:grid;gap:12px'>{''.join(items)}</div>"
        )

        # CO ANALIZUJEMY
        pair_rows = []
        for i in range(0, len(EYES_ORDER), 2):
            pair = EYES_ORDER[i:i + 2]
            row = "<div style='display:flex;gap:20px;margin:20px 0 10px 0;flex-wrap:wrap'>"
            for tid in pair:
                meta = EYES_DATA.get(tid, {})
                icon = meta.get("icon", "🔎")
                title = meta.get("label", tid)
                lines = meta.get("analyze", [])
                text = " ".join(lines[:4])
                row += f"""
                  <div style="flex:1;min-width:280px;padding:14px;border-radius:12px;background:#0e1016;
                              box-shadow:0 2px 10px rgba(0,0,0,.28)">
                    <div style="display:flex;gap:10px;align-items:flex-start">
                      <div style="font-size:22px">{icon}</div>
                      <div>
                        <div style="font-weight:700">{title}</div>
                        <div style="font-size:13px;line-height:1.55;opacity:.92;margin-top:4px">{text}</div>
                      </div>
                    </div>
                  </div>
                """
            row += "</div>"
            pair_rows.append(row)
        analyze_html = (
            "<div style='margin-top:16px;margin-bottom:6px;font-weight:700;border-left:4px solid #3b82f6;padding-left:8px'>"
            "Co analizujemy (stałe obszary audytu)</div>"
            + "".join(pair_rows)
        )
        return header + detected_html + analyze_html, 200, {"Content-Type": "text/html; charset=utf-8"}

    except Exception as e:
        return f"<pre>Błąd renderowania: {e}</pre>", 500, {"Content-Type": "text/html; charset=utf-8"}

# ------------------- MAIN -------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)
