#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from flask import Flask, request, jsonify, send_from_directory
import subprocess, os, time, re, glob, json
import requests
from datetime import datetime, timezone

APP_ROOT = os.path.dirname(os.path.abspath(__file__))
ANALYZE_DIR = os.path.join(APP_ROOT, "ANALYZE")
LOGS_DIR = os.path.join(APP_ROOT, "LOGS")
ANALYZE_BY_ID_DIR = os.path.join(ANALYZE_DIR, "by_id")

# ⬇️ Twój analizator (zostawiamy jak było)
ANALYZER_CMD = "python anty_scam.py {address}"
ANALYZE_TIMEOUT_SEC = 180

# ETH address regex
ADDRESS_RE = re.compile(r"^0x[a-fA-F0-9]{40}$")

# Outseta ENV (opcjonalne)
OUTSETA_DOMAIN = os.getenv("OUTSETA_DOMAIN", "").strip()
OUTSETA_KEY    = os.getenv("OUTSETA_API_KEY", "").strip()
OUTSETA_SECRET = os.getenv("OUTSETA_API_SECRET", "").strip()

app = Flask(__name__, static_folder="assets", static_url_path="/assets")

# --------- EYES overlay (bez zmian) ----------
EYES_PATH = os.path.join(APP_ROOT, "eyes.json")
EYES_DATA = {}
EYES_ORDER = []

def _load_eyes():
    global EYES_DATA, EYES_ORDER
    try:
        with open(EYES_PATH, "r", encoding="utf-8") as f:
            arr = json.load(f)
        EYES_DATA = {e["key"]: e for e in arr}
        EYES_ORDER = [e["key"] for e in arr]
        print(f"[EYES] Loaded {len(EYES_ORDER)} items from eyes.json")
    except Exception as e:
        EYES_DATA, EYES_ORDER = {}, []
        print(f"[EYES][WARN] Could not load eyes.json: {e}")

_load_eyes()

def tail_text(txt: str, max_len: int = 2000) -> str:
    return txt if len(txt) <= max_len else txt[-max_len:]

# ---- NEW: wybór raportu z ANALYZE/by_id (z opcjonalnym filtrem czasowym) ----
def latest_report_by_id(after_ts: float | None = None) -> str:
    if not os.path.isdir(ANALYZE_BY_ID_DIR):
        return ""
    files = glob.glob(os.path.join(ANALYZE_BY_ID_DIR, "*.json"))
    if after_ts is not None:
        files = [p for p in files if os.path.getmtime(p) >= after_ts]
    if not files:
        return ""
    files.sort(key=os.path.getmtime, reverse=True)
    return files[0]

def latest_report_path() -> str:
    """
    Najpierw szukamy w ANALYZE/by_id/*.json (nowy I/O).
    Jeśli nic nie ma, fallback do dawnych katalogów (GOOD/RISK/EXTREME_RISK).
    """
    p = latest_report_by_id()
    if p:
        return p
    files = []
    for sub in ["GOOD", "RISK", "EXTREME_RISK"]:
        files.extend(glob.glob(os.path.join(ANALYZE_DIR, sub, "*.txt")))
        files.extend(glob.glob(os.path.join(ANALYZE_DIR, sub, "*.json")))
    if not files:
        return ""
    files.sort(key=os.path.getmtime, reverse=True)
    return files[0]

# ---------- Outseta helpers ----------
def _outseta_configured() -> bool:
    return bool(OUTSETA_DOMAIN and OUTSETA_KEY and OUTSETA_SECRET)

def outseta_get(path, params=None):
    # Jeśli Outseta nie jest skonfigurowana – sygnalizujemy to łagodnie
    if not _outseta_configured():
        raise RuntimeError("OUTSETA_DISABLED")
    url = f"https://{OUTSETA_DOMAIN}{path}"
    headers = {
        "Authorization": f"Outseta {OUTSETA_KEY}:{OUTSETA_SECRET}",
        "Accept": "application/json",
    }
    r = requests.get(url, params=params or {}, headers=headers, timeout=15)
    r.raise_for_status()
    return r.json()

def _iso_to_dt(s: str):
    if not s: return None
    try:
        s_norm = s.replace("Z", "+00:00")
        return datetime.fromisoformat(s_norm)
    except Exception:
        return None

def has_active_or_trial(email: str) -> bool:
    """
    Dostęp tylko dla:
      • AccountStage ∈ {2, 3} (2=Trialing, 3=Subscribed/Active)
      • LUB CurrentSubscription.Status ∈ {active, trial, trialing}
      • Fallback: 'trial' w nazwie etapu lub TrialEnds* w przyszłości

    Jeśli Outseta ENV nie ustawione → True (nie blokujemy analizy; front nadal pilnuje).
    """
    if not email:
        return False

    if not _outseta_configured():
        return True

    fields = (
        "Uid,FirstName,LastName,Email,"
        "PersonAccount.*,PersonAccount.IsPrimary,"
        "PersonAccount.Account.*,PersonAccount.Account.Name,"
        "PersonAccount.Account.AccountStage,"
        "PersonAccount.Account.AccountStageName,"
        "PersonAccount.Account.StageName,"
        "PersonAccount.Account.TrialEndsAt,"
        "PersonAccount.Account.TrialEndDate,"
        "PersonAccount.Account.TrialEndsOn,"
        "PersonAccount.Account.CurrentSubscription.*"
    )
    data = outseta_get("/api/v1/crm/people", params={"Email": email, "fields": fields})
    items = data.get("items", []) if isinstance(data, dict) else []
    if not items:
        return False

    person = items[0]
    pas = person.get("PersonAccount") or []
    if not pas:
        return False

    pa = next((x for x in pas if x.get("IsPrimary")), pas[0])
    account = pa.get("Account") or {}

    # 1) twarde kody
    stage_code = account.get("AccountStage")
    try:
        stage_code_int = int(stage_code)
    except (TypeError, ValueError):
        stage_code_int = None
    if stage_code_int in (2, 3):
        return True

    # 2) billing status
    subs = account.get("CurrentSubscription") or {}
    sub_status = (subs.get("Status") or subs.get("State") or "").strip().lower()
    if sub_status in ("active", "trial", "trialing"):
        return True

    # 3) nazwa etapu „trial”
    stage_name = (
        account.get("AccountStageName")
        or account.get("StageName")
        or str(stage_code if stage_code is not None else "")
    )
    if "trial" in str(stage_name).lower():
        return True

    # 4) okno triala
    trial_ends = account.get("TrialEndsAt") or account.get("TrialEndDate") or account.get("TrialEndsOn")
    dt = _iso_to_dt(trial_ends) if trial_ends else None
    if dt:
        if not dt.tzinfo:
            dt = dt.replace(tzinfo=timezone.utc)
        if dt > datetime.now(timezone.utc):
            return True

    return False

# ---------- ROUTES / PUBLIC API ENDPOINTS (UI + ANALYZE) ----------
@app.route("/")
def home():
    return open(os.path.join(APP_ROOT, "index.html"), "r", encoding="utf-8").read()

@app.route("/health")
def health():
    return jsonify({"status": "ok", "time": int(time.time())})

@app.route("/analyze", methods=["POST"])
def analyze():
    email = (request.headers.get("X-User-Email") or "").strip().lower()

    # ✅ Backend gating tylko gdy Outseta skonfigurowana; inaczej nie blokujemy
    try:
        if _outseta_configured():
            if not has_active_or_trial(email):
                return jsonify({"error":"access_denied","message":"Aktywuj plan lub trial w Profil / Płatności."}), 403
    except Exception as e:
        if str(e) != "OUTSETA_DISABLED":
            return jsonify({"error":"subscription_check_failed","message":str(e)}), 403

    address = (request.form.get("address") or "").strip()
    if not ADDRESS_RE.match(address):
        return jsonify({"error": "Invalid ETH address. Expected 0x + 40 hex chars."}), 400

    # zapamiętaj czas startu; po analizie wybierz najnowszy plik z by_id ≥ start_ts
    start_ts = time.time()
    cmd = ANALYZER_CMD.format(address=address)
    try:
        proc = subprocess.run(
            cmd, cwd=APP_ROOT, shell=True,
            capture_output=True, text=True,
            timeout=ANALYZE_TIMEOUT_SEC
        )
        elapsed = round(time.time() - start_ts, 2)
        status = "ok" if proc.returncode == 0 else "error"

        # NEW: wskaż raport powstały w TYM żądaniu
        report_path = latest_report_by_id(after_ts=start_ts) or latest_report_path()
        report_rel = os.path.relpath(report_path, APP_ROOT) if report_path else None

        # NEW: małe podsumowanie z raportu (name / score / decision)
        summary = None
        if report_path:
            try:
                with open(report_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                if isinstance(data, list) and data:
                    data = data[-1]
                if isinstance(data, dict):
                    summary = {
                        "name": (data.get("identity", {}).get("resolved_name")
                                 or data.get("name")),
                        "address": data.get("address"),
                        "score": data.get("score"),
                        "decision": data.get("decision"),
                        "risk_level": data.get("risk_level"),
                    }
            except Exception:
                summary = None

        return jsonify({
            "status": status,
            "elapsed_sec": elapsed,
            "address": address,
            "cmd": cmd,
            "stdout_tail": tail_text(proc.stdout, 4000),
            "stderr_tail": tail_text(proc.stderr, 2000),
            "last_report": report_rel,
            "summary": summary
        }), (200 if status == "ok" else 500)
    except subprocess.TimeoutExpired:
        return jsonify({"error": f"Analyzer timed out after {ANALYZE_TIMEOUT_SEC}s", "address": address}), 504

@app.route("/assets/<path:filename>")
def assets(filename):
    return send_from_directory(os.path.join(APP_ROOT, "assets"), filename)

@app.route("/static/<path:filename>")
def static_files(filename):
    return send_from_directory(os.path.join(APP_ROOT, "static"), filename)

# ---------- HTML overlay (bez zmian funkcjonalnych) ----------
def _parse_first_line_csv(txt: str):
    for ln in txt.splitlines():
        s = ln.strip()
        if not s: continue
        parts = [p.strip() for p in s.split(",")]
        if len(parts) >= 4 and ADDRESS_RE.match(parts[1]):
            return {"name": parts[0], "address": parts[1], "score": parts[2], "label": parts[3]}
        break
    return None

def _badge_by_score(sc: float) -> str:
    if sc >= 8: return "<span style='padding:6px 12px;border-radius:999px;background:#1c8f4d;color:#fff;font-weight:700'>GOOD</span>"
    if sc >= 5: return "<span style='padding:6px 12px;border-radius:999px;background:#ffb703;color:#111;font-weight:700'>RISK</span>"
    return "<span style='padding:6px 12px;border-radius:999px;background:#d62828;color:#fff;font-weight:700'>EXTREME</span>"

MAP_RULES = [
    ("honeypot", "honeypot"), ("honeypot/", "honeypot"),
    ("podatk", "high_tax"), ("fee", "high_tax"), ("high tax", "high_tax"),
    ("dodruk", "mint_unlimited"), ("mint", "mint_unlimited"),
    ("100%", "constructor_mint_msgsender"), ("owner", "constructor_mint_msgsender"),
    ("blacklist", "blacklist_trading"), ("blok", "blacklist_trading"),
    ("pauz", "pause_control"), ("wstrzym", "pause_control"),
    ("withdraw", "withdraw_stuck"), ("wypł", "withdraw_stuck"),
    ("kill", "kill_switch_v2"), ("proxy", "proxy_like"),
    ("router", "router_exception"), ("dex", "router_exception"),
    ("obfusk", "assembly_obfuscation"), ("assembly", "assembly_obfuscation"),
    ("reflection", "reflection_tax"), ("dynamic", "dynamic_fee"),
    ("max wallet", "max_wallet"), ("max tx", "max_tx"),
    ("whitelist", "whitelist_only"), ("trading not open", "trading_not_open"),
    ("hidden owner", "hidden_owner"), ("reentrancy", "reentrancy_risk"),
    ("overflow", "overflow_risk"), ("timestamp", "timestamp_dependence"),
    ("liquidity", "liquidity_removable"), ("audit", "scam_audit_fake"),
    ("external call", "external_call_unchecked"),
]

def _normalize_detected_from_json(report: dict) -> list:
    out, candidates = [], []
    for key in ["threats", "flags", "issues", "detections"]:
        v = report.get(key)
        if not v: continue
        if isinstance(v, list): candidates.extend([str(x) for x in v])
        elif isinstance(v, dict):
            for k, val in v.items():
                if val: candidates.append(k)
    for s in candidates:
        s_l = s.strip().lower()
        if s_l in EYES_DATA and s_l not in out: out.append(s_l)
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
        if ext == ".json":
            data = json.load(open(path, "r", encoding="utf-8", errors="ignore"))
            report = data[-1] if isinstance(data, list) and data else (data if isinstance(data, dict) else {})
            name = report.get("identity", {}).get("resolved_name") or report.get("name") or "Contract"
            addr = report.get("address", "?")
            try: score = float(report.get("score", 0.0))
            except Exception: score = 0.0
            badge = _badge_by_score(score)
            bar_w = max(0, min(100, int((score/10.0)*100)))
            header = f"""
            <div style="padding:16px;margin-bottom:12px;background:#0f1114;border-radius:12px;box-shadow:0 2px 12px rgba(0,0,0,.35)">
              <div style="display:flex;gap:12px;align-items:center;flex-wrap:wrap">
                {badge}
                <div style="font-weight:700;font-size:18px">{name}</div>
                <div style="margin-left:auto;color:#9aa0a6;font-size:12px">Plik: {rel}</div>
              </div>
              <div style="margin-top:8px;color:#cfd6dc">
                <div><small>Adres:</small> <code>{addr}</code></div>
                <div style="margin-top:6px"><small>Wynik:</small> {score:.2f} / 10</div>
                <div style="margin-top:8px"><div style="height:8px;border-radius:999px;background:#222;overflow:hidden">
                  <span style="display:block;height:100%;width:{bar_w}%;background:linear-gradient(90deg,#3b82f6,#22c55e)"></span>
                </div></div>
              </div>
            </div>"""
            detected_html = """
              <div style="margin-top:10px;margin-bottom:8px;color:#cfd6dc;font-size:13px;line-height:1.6;opacity:.95">
                🤝 <strong>Ocena to efekt analizy kodu przez silnik CIS Aurora</strong> — pamiętaj o własnym researchu (DYOR).<br>
                To nie są porady inwestycyjne — decyzje podejmuj samodzielnie.<br>
                <span style="opacity:.85">💛 Dziękujemy za zaufanie i wsparcie.</span>
              </div>"""
            pair_rows, keys = [], (EYES_ORDER[:] if EYES_ORDER else list(EYES_DATA.keys()))
            for i in range(0, len(keys), 2):
                pair = keys[i:i+2]
                row = "<div style='display:flex;gap:20px;margin:20px 0 10px 0;flex-wrap:wrap'>"
                for tid in pair:
                    meta = EYES_DATA.get(tid, {})
                    icon = meta.get("icon", "🔎")
                    title = meta.get("label", tid)
                    lines = meta.get("analyze", [])
                    text = " ".join(lines[:4])
                    row += f"""
                      <div style="flex:1;min-width:280px;padding:14px;border-radius:12px;background:#0e1016;box-shadow:0 2px 10px rgba(0,0,0,.28)">
                        <div style="display:flex;gap:10px;align-items:flex-start">
                          <div style="font-size:22px">{icon}</div>
                          <div><div style="font-weight:700">{title}</div>
                          <div style="font-size:13px;line-height:1.55;opacity:.92;margin-top:4px">{text}</div></div>
                        </div>
                      </div>"""
                row += "</div>"
                pair_rows.append(row)
            analyze_html = ("<div style='margin-top:16px;margin-bottom:6px;font-weight:700;border-left:4px solid #3b82f6;padding-left:8px'>Co analizujemy (stałe obszary audytu)</div>" + "".join(pair_rows))
            return header + detected_html + analyze_html, 200, {"Content-Type": "text/html; charset=utf-8"}

        txt = open(path, "r", encoding="utf-8", errors="ignore").read()
        item = _parse_first_line_csv(txt) or {"name": "?", "address": "?", "score": "0", "label": "RISK"}
        name = item.get("name", "?"); addr = item.get("address", "?")
        try: score = float(item.get("score", 0.0))
        except Exception: score = 0.0
        badge = _badge_by_score(score); bar_w = max(0, min(100, int((score/10.0)*100)))
        header = f"""
        <div style="padding:16px;margin-bottom:12px;background:#0f1114;border-radius:12px;box-shadow:0 2px 12px rgba(0,0,0,.35)">
          <div style="display:flex;gap:12px;align-items:center;flex-wrap:wrap">
            {badge}<div style="font-weight:700;font-size:18px">{name}</div>
            <div style="margin-left:auto;color:#9aa0a6;font-size:12px">Plik: {os.path.relpath(path, APP_ROOT)}</div>
          </div>
          <div style="margin-top:8px;color:#cfd6dc">
            <div><small>Adres:</small> <code>{addr}</code></div>
            <div style="margin-top:6px"><small>Wynik:</small> {score:.2f} / 10</div>
            <div style="margin-top:8px"><div style="height:8px;border-radius:999px;background:#222;overflow:hidden">
              <span style="display:block;height:100%;width:{bar_w}%;background:linear-gradient(90deg,#3b82f6,#22c55e)"></span>
            </div></div>
          </div>
        </div>"""
        detected_html = """
          <div style="margin-top:10px;margin-bottom:8px;color:#cfd6dc;font-size:13px;line-height:1.6;opacity:.95">
            🤝 <strong>Ocena to efekt analizy kodu przez silnik CIS Aurora</strong> — pamiętaj o własnym researchu (DYOR).<br>
            To nie są porady inwestycyjne — decyzje podejmuj samodzielnie.<br>
            <span style="opacity:.85">💛 Dziękujemy za zaufanie i wsparcie.</span>
          </div>"""
        pair_rows, keys = [], (EYES_ORDER[:] if EYES_ORDER else list(EYES_DATA.keys()))
        for i in range(0, len(keys), 2):
            pair = keys[i:i+2]
            row = "<div style='display:flex;gap:20px;margin:20px 0 10px 0;flex-wrap:wrap'>"
            for tid in pair:
                meta = EYES_DATA.get(tid, {})
                icon = meta.get("icon", "🔎"); title = meta.get("label", tid)
                lines = meta.get("analyze", []); text = " ".join(lines[:4])
                row += f"""
                  <div style="flex:1;min-width:280px;padding:14px;border-radius:12px;background:#0e1016;box-shadow:0 2px 10px rgba(0,0,0,.28)">
                    <div style="display:flex;gap:10px;align-items:flex-start">
                      <div style="font-size:22px">{icon}</div>
                      <div><div style="font-weight:700'>{title}</div>
                      <div style="font-size:13px;line-height:1.55;opacity:.92;margin-top:4px">{text}</div></div>
                    </div>
                  </div>"""
            row += "</div>"; pair_rows.append(row)
        analyze_html = ("<div style='margin-top:16px;margin-bottom:6px;font-weight:700;border-left:4px solid #3b82f6;padding-left:8px'>Co analizujemy (stałe obszary audytu)</div>" + "".join(pair_rows))
        return header + detected_html + analyze_html, 200, {"Content-Type": "text/html; charset=utf-8"}

    except Exception as e:
        return f"<pre>{e}</pre>", 500, {"Content-Type": "text/html; charset=utf-8"}

if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    app.run(host="0.0.0.0", port=port, debug=False)
