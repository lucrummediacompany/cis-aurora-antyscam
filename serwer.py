#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from flask import Flask, request, jsonify, send_from_directory
import subprocess, os, time, re, glob, json
import requests
from datetime import datetime, timezone
import smtplib
from email.mime.text import MIMEText
from core_hearth.analyzer_core_hearth import fetch_contract_source, analyze_contract

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

# SMTP / Gmail – zgłoszenia "Nie zgadzasz się z oceną?"
SMTP_HOST = os.getenv("SMTP_HOST", "smtp.gmail.com").strip()
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER", "").strip()
SMTP_PASS = os.getenv("SMTP_PASS", "").strip()
SMTP_FROM = os.getenv("SMTP_FROM", SMTP_USER).strip()
SMTP_TO   = os.getenv("SMTP_TO", "lucrum.media.company@gmail.com").strip()


def _smtp_configured() -> bool:
    return bool(SMTP_HOST and SMTP_USER and SMTP_PASS and SMTP_FROM and SMTP_TO)


def send_disagreement_email(address: str, user_email: str) -> bool:
    """
    Wysyła proste zgłoszenie e-mail na adres supportowy,
    gdy użytkownik nie zgadza się z oceną kontraktu.
    """
    if not _smtp_configured():
        print("[DISAGREE][WARN] SMTP not configured; skipping email.")
        return False

    subject = "CIS Aurora — zgłoszenie kontraktu do ręcznej analizy"

    body = (
        "Adres kontraktu: {addr}\n"
        "Użytkownik (e-mail w Outseta / aplikacji): {user}\n\n"
        "Użytkownik zgłosił, że nie zgadza się z oceną tego kontraktu.\n"
        "Możesz odpisać bezpośrednio do użytkownika i poprosić o więcej szczegółów."
    ).format(
        addr=address,
        user=user_email or "nieznany",
    )

    try:
        msg = MIMEText(body, _charset="utf-8")
        msg["Subject"] = subject
        msg["From"] = SMTP_FROM
        msg["To"] = SMTP_TO

        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=20) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASS)
            server.sendmail(SMTP_FROM, [SMTP_TO], msg.as_string())

        print(f"[DISAGREE] Email sent for {address}")
        return True
    except Exception as e:
        print(f"[DISAGREE][ERROR] {e}")
        return False

app = Flask(__name__, static_folder="assets", static_url_path="/assets")


# --------- EYES overlay ----------
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


# ---------- CIS CYBER SHIELD — RATE LIMIT / BAN LIST ----------
RATE_WINDOW_SEC = 5          # okno liczenia requestów
RATE_SOFT_LIMIT = 10         # soft limit (ostrzeżenie)
RATE_HARD_LIMIT = 20         # twardy limit (natychmiastowy ban)
BAN_DURATION_SEC = 3600      # 1h bana
SOFT_STRIKES_LIMIT = 3       # ile razy można przekroczyć soft limit zanim wpadnie ban

REQUEST_LOG = {}             # ip -> [timestamps]
SOFT_STRIKES = {}            # ip -> liczba soft-strike'ów
BANNED_IPS = {}              # ip -> ban_until_timestamp


def _now() -> float:
    return time.time()


def _get_client_ip() -> str:
    """
    Pobierz IP klienta z X-Forwarded-For (Render / proxy) lub remote_addr.
    """
    xff = request.headers.get("X-Forwarded-For", "")
    if xff:
        return xff.split(",")[0].strip()
    return request.remote_addr or "unknown"


def _cleanup_ip_window(ip: str, now: float) -> int:
    """
    Czyści stare wpisy dla IP spoza okna RATE_WINDOW_SEC.
    Zwraca aktualną liczbę requestów w oknie.
    """
    lst = REQUEST_LOG.get(ip)
    if not lst:
        return 0
    lst = [t for t in lst if now - t <= RATE_WINDOW_SEC]
    if lst:
        REQUEST_LOG[ip] = lst
    else:
        REQUEST_LOG.pop(ip, None)
    return len(lst)


def _is_ip_banned(ip: str) -> bool:
    """
    Sprawdza, czy IP jest zbanowane (i czy ban nie wygasł).
    """
    now = _now()
    banned_until = BANNED_IPS.get(ip)
    if not banned_until:
        return False
    if now >= banned_until:
        # ban wygasł – czyścimy
        BANNED_IPS.pop(ip, None)
        SOFT_STRIKES.pop(ip, None)
        return False
    return True


def _register_request_for_ip(ip: str) -> str:
    """
    Rejestruje pojedynczy request dla ip i zwraca status:
      • "ok"          – w limicie
      • "soft"        – przekroczony soft-limit (ale jeszcze bez bana)
      • "banned_soft" – ban po wielokrotnym przekroczeniu soft-limit
      • "banned_hard" – natychmiastowy ban (HARD_LIMIT)
    """
    now = _now()
    # Czy ban wygasł:
    _is_ip_banned(ip)

    # Jeśli dalej banned – nic nie liczymy
    if ip in BANNED_IPS:
        return "banned_hard"

    count = _cleanup_ip_window(ip, now)
    count += 1
    REQUEST_LOG.setdefault(ip, []).append(now)

    # Twardy limit — ewidentny flood
    if count > RATE_HARD_LIMIT:
        BANNED_IPS[ip] = now + BAN_DURATION_SEC
        return "banned_hard"

    # Soft limit — ostrzeżenie + liczenie strike'ów
    if count > RATE_SOFT_LIMIT:
        strikes = SOFT_STRIKES.get(ip, 0) + 1
        SOFT_STRIKES[ip] = strikes
        if strikes >= SOFT_STRIKES_LIMIT:
            BANNED_IPS[ip] = now + BAN_DURATION_SEC
            return "banned_soft"
        return "soft"

    return "ok"


def _headers_look_like_bot() -> bool:
    """
    Minimalna heurystyka do wykrywania botów:
      • pusty User-Agent
      • brak nagłówka Accept (typowe dla curl/skryptów bez przeglądarki)
    """
    ua = (request.headers.get("User-Agent") or "").strip()
    if not ua:
        return True
    accept = request.headers.get("Accept")
    if not accept:
        return True
    return False


# ---- Raporty ANALYZE/by_id ----
def latest_report_by_id(after_ts: float | None = None) -> str:
    """Zwraca NAJNowszy raport z ANALYZE/by_id/*.json, opcjonalnie tylko >= after_ts."""
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
    Fallback: gdy nie podano konkretnego path (tylko do ręcznego wejścia na /last-report-html).
    NIE jest używane w /analyze do obsługi błędów.
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
    if not s:
        return None
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
    trial_ends = (
        account.get("TrialEndsAt")
        or account.get("TrialEndDate")
        or account.get("TrialEndsOn")
    )
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
    ip = _get_client_ip()

    # 🔒 1) Ban-lista — IP już zbanowane?
    if _is_ip_banned(ip):
        # Obliczamy pozostały czas bana (jeśli jeszcze jest)
        now = _now()
        ban_until = BANNED_IPS.get(ip, now)
        remaining = max(0, int(ban_until - now))
        return (
            jsonify(
                {
                    "error": "rate_limited",
                    "message": "Zbyt wiele zapytań z tego adresu IP. Spróbuj ponownie później.",
                    "retry_after_sec": remaining,
                }
            ),
            429,
        )

    # 🔍 2) Heurystyka botów — pusty UA / brak Accept
    if _headers_look_like_bot():
        # od razu ban na 1h – ruch ewidentnie nie przeglądarkowy
        BANNED_IPS[ip] = _now() + BAN_DURATION_SEC
        return (
            jsonify(
                {
                    "error": "bot_detected",
                    "message": "Ruch wygląda jak automatyczny (bot/skrypt). Dostęp zablokowany.",
                }
            ),
            403,
        )

    # ⏱ 3) Rejestrujemy request w oknie RATE_WINDOW_SEC
    rl_status = _register_request_for_ip(ip)
    if rl_status in ("banned_hard", "banned_soft"):
        return (
            jsonify(
                {
                    "error": "rate_limited",
                    "message": "Zbyt wiele zapytań z tego adresu IP. Spróbuj ponownie później.",
                    "retry_after_sec": BAN_DURATION_SEC,
                }
            ),
            429,
        )
    # rl_status == "soft" lub "ok" – dla frontu działamy normalnie

    email = (request.headers.get("X-User-Email") or "").strip().lower()

    # ✅ Backend gating tylko gdy Outseta skonfigurowana; inaczej nie blokujemy
    try:
        if _outseta_configured():
            if not has_active_or_trial(email):
                return (
                    jsonify(
                        {
                            "error": "access_denied",
                            "message": "Aktywuj plan lub trial w Profil / Płatności.",
                        }
                    ),
                    403,
                )
    except Exception as e:
        if str(e) != "OUTSETA_DISABLED":
            return (
                jsonify(
                    {
                        "error": "subscription_check_failed",
                        "message": str(e),
                    }
                ),
                403,
            )

    address = (request.form.get("address") or request.form.get("contract_address") or "").strip()
    if not ADDRESS_RE.match(address):
        return (
            jsonify(
                {
                    "error": "invalid_address",
                    "message": "Podany adres nie jest prawidłowym adresem Ethereum (musi mieć format 0x + 40 znaków szesnastkowych).",
                }
            ),
            400,
        )

    # zapamiętaj czas startu; po analizie wybierz nowy plik z by_id >= start_ts
    start_ts = time.time()
    cmd = ANALYZER_CMD.format(address=address)

    try:
        proc = subprocess.run(
            cmd,
            cwd=APP_ROOT,
            shell=True,
            capture_output=True,
            text=True,
            timeout=ANALYZE_TIMEOUT_SEC,
        )
        elapsed = round(time.time() - start_ts, 2)

        stdout = proc.stdout or ""
        stderr = proc.stderr or ""

        # 🔎 1) Brak źródła – kontrakt niezweryfikowany na Etherscan
        no_source = (
            ("Brak źródła dla" in stdout)
            or ("Brak zrodla dla" in stdout)
            or ("NO_SOURCE" in stdout.upper())
        )
        if no_source:
            return (
                jsonify(
                    {
                        "status": "no_source",
                        "address": address,
                        "elapsed_sec": elapsed,
                        "message": "Brak kodu źródłowego na Etherscan dla tego adresu (kontrakt nie jest zweryfikowany).",
                        "stdout_tail": tail_text(stdout, 4000),
                        "stderr_tail": tail_text(stderr, 2000),
                        "last_report": None,
                        "summary": None,
                    }
                ),
                200,
            )

        # 🔎 2) Szukamy raportu TYLKO po ANALYZE/by_id i TYLKO po czasie startu
        report_path = latest_report_by_id(after_ts=start_ts)
        if not report_path:
            # brak nowego raportu dla tego żądania
            return (
                jsonify(
                    {
                        "status": "no_report",
                        "address": address,
                        "elapsed_sec": elapsed,
                        "message": "Analiza nie zapisała raportu (brak pliku w ANALYZE/by_id dla tego żądania). Spróbuj ponownie.",
                        "stdout_tail": tail_text(stdout, 4000),
                        "stderr_tail": tail_text(stderr, 2000),
                        "last_report": None,
                        "summary": None,
                    }
                ),
                200,
            )

        # ✅ 3) Mamy by_id – budujemy odpowiedź dla frontu
        status = "ok" if proc.returncode == 0 else "error"
        report_rel = os.path.relpath(report_path, APP_ROOT)

        summary = None
        try:
            with open(report_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, list) and data:
                data = data[-1]
            if isinstance(data, dict):
                summary = {
                    "name": (
                        data.get("identity", {}).get("resolved_name")
                        or data.get("name")
                    ),
                    "address": data.get("address"),
                    "score": data.get("score"),
                    "decision": data.get("decision"),
                    "risk_level": data.get("risk_level"),
                }
        except Exception:
            summary = None

        return (
            jsonify(
                {
                    "status": status,
                    "elapsed_sec": elapsed,
                    "address": address,
                    "cmd": cmd,
                    "stdout_tail": tail_text(stdout, 4000),
                    "stderr_tail": tail_text(stderr, 2000),
                    "last_report": report_rel,
                    "summary": summary,
                }
            ),
            (200 if status == "ok" else 500),
        )

    except subprocess.TimeoutExpired:
        # timeout analizatora – potencjalny symptom floodu / problemu po stronie core
        return (
            jsonify(
                {
                    "error": "timeout",
                    "message": f"Analyzer timed out after {ANALYZE_TIMEOUT_SEC}s",
                    "address": address,
                }
            ),
            504,
        )


@app.route("/hearth-analyze", methods=["POST"])
def hearth_analyze():
    """
    Wewnętrzny endpoint dla SERCA.
    Przyjmuje JSON {"address": "0x..."} i zwraca wynik z analyzer_core_hearth.py.
    """
    data = request.get_json(silent=True) or {}
    address = (data.get("address") or "").strip()

    if not ADDRESS_RE.match(address):
        return (
            jsonify(
                {
                    "ok": False,
                    "error": "invalid_address",
                    "message": "Podany adres nie jest prawidłowym adresem Ethereum (musi mieć format 0x + 40 znaków szesnastkowych).",
                }
            ),
            400,
        )

    try:
        src = fetch_contract_source(address)
        if not src:
            return (
                jsonify(
                    {
                        "ok": False,
                        "error": "no_source",
                        "message": "Brak kodu źródłowego na Etherscan dla tego adresu (kontrakt nie jest zweryfikowany).",
                    }
                ),
                200,
            )

        report = analyze_contract("Contract", address, src, contract_meta=None)
        if not isinstance(report, dict):
            return (
                jsonify(
                    {
                        "ok": False,
                        "error": "bad_report",
                        "message": "Silnik zwrócił nieprawidłowy raport.",
                    }
                ),
                500,
            )

        score = float(report.get("score", 0.0) or 0.0)
        risk_level = report.get("risk_level") or ""
        decision = report.get("decision") or ""
        bucket = report.get("bucket") or ""

        return (
            jsonify(
                {
                    "ok": True,
                    "address": address,
                    "score": score,
                    "risk_level": risk_level,
                    "decision": decision,
                    "bucket": bucket,
                    "report": report,
                }
            ),
            200,
        )

    except Exception as e:
        return (
            jsonify(
                {
                    "ok": False,
                    "error": "internal_error",
                    "message": str(e),
                }
            ),
            500,
        )


@app.route("/send-disagreement", methods=["POST"])
def send_disagreement():
    """
    End-point do zgłaszania kontraktów, z których oceną użytkownik się nie zgadza.
    Chroniony tą samą tarczą (rate-limit / ban) co /analyze.
    """
    ip = _get_client_ip()

    # 1) Ban – jeśli IP już zbanowane
    if _is_ip_banned(ip):
        now = _now()
        ban_until = BANNED_IPS.get(ip, now)
        remaining = max(0, int(ban_until - now))
        return (
            jsonify(
                {
                    "error": "rate_limited",
                    "message": "Zbyt wiele zapytań z tego adresu IP. Spróbuj ponownie później.",
                    "retry_after_sec": remaining,
                }
            ),
            429,
        )

    # 2) Rejestrujemy request w oknie czasowym
    rl_status = _register_request_for_ip(ip)
    if rl_status in ("banned_hard", "banned_soft"):
        return (
            jsonify(
                {
                    "error": "rate_limited",
                    "message": "Zbyt wiele zapytań z tego adresu IP. Spróbuj ponownie później.",
                    "retry_after_sec": BAN_DURATION_SEC,
                }
            ),
            429,
        )

    address = (request.form.get("address") or "").strip()
    user_email = (request.form.get("user_email") or "").strip()

    if not ADDRESS_RE.match(address):
        return (
            jsonify(
                {
                    "error": "invalid_address",
                    "message": "Podany adres nie jest prawidłowym adresem Ethereum (musi mieć format 0x + 40 znaków).",
                }
            ),
            400,
        )

    sent = send_disagreement_email(address, user_email)
    if not sent:
        return (
            jsonify(
                {
                    "status": "error",
                    "message": "Nie udało się wysłać zgłoszenia e-mail (SMTP nie jest skonfigurowane lub wystąpił błąd wysyłki).",
                }
            ),
            500,
        )

    return jsonify({"status": "ok", "message": "Zgłoszenie zostało wysłane. Dziękujemy!"})


@app.route("/assets/<path:filename>")
def assets(filename):
    return send_from_directory(os.path.join(APP_ROOT, "assets"), filename)


@app.route("/static/<path:filename>")
def static_files(filename):
    return send_from_directory(os.path.join(APP_ROOT, "static"), filename)


# ---------- HTML overlay ----------
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
    if sc >= 8.0:
        # GO
        return "<span style='padding:6px 12px;border-radius:999px;background:#1c8f4d;color:#fff;font-weight:700'>GO</span>"
    if sc >= 6.60:
        # REVIEW
        return "<span style='padding:6px 12px;border-radius:999px;background:#ffb703;color:#111;font-weight:700'>REVIEW</span>"
    # NO-GO
    return "<span style='padding:6px 12px;border-radius:999px;background:#d62828;color:#fff;font-weight:700'>NO-GO</span>"


def _badge_for_decision(decision: str, score: float) -> str:
    """
    Badge przede wszystkim wg decyzji z core (GO / REVIEW / NO-GO).
    Jeśli brak decyzji – używamy progów ze score.
    """
    d = (decision or "").upper()
    if d == "GO":
        return _badge_by_score(9.0)
    if d == "REVIEW":
        return _badge_by_score(7.0)
    if d == "NO-GO":
        return _badge_by_score(0.0)
    return _badge_by_score(score)


MAP_RULES = [
    ("honeypot", "honeypot"),
    ("honeypot/", "honeypot"),
    ("podatk", "high_tax"),
    ("fee", "high_tax"),
    ("high tax", "high_tax"),
    ("dodruk", "mint_unlimited"),
    ("mint", "mint_unlimited"),
    ("100%", "constructor_mint_msgsender"),
    ("owner", "constructor_mint_msgsender"),
    ("blacklist", "blacklist_trading"),
    ("blok", "blacklist_trading"),
    ("pauz", "pause_control"),
    ("wstrzym", "pause_control"),
    ("withdraw", "withdraw_stuck"),
    ("wypł", "withdraw_stuck"),
    ("kill", "kill_switch_v2"),
    ("proxy", "proxy_like"),
    ("router", "router_exception"),
    ("dex", "router_exception"),
    ("obfusk", "assembly_obfuscation"),
    ("assembly", "assembly_obfuscation"),
    ("reflection", "reflection_tax"),
    ("dynamic", "dynamic_fee"),
    ("max wallet", "max_wallet"),
    ("max tx", "max_tx"),
    ("whitelist", "whitelist_only"),
    ("trading not open", "trading_not_open"),
    ("hidden owner", "hidden_owner"),
    ("reentrancy", "reentrancy_risk"),
    ("overflow", "overflow_risk"),
    ("timestamp", "timestamp_dependence"),
    ("liquidity", "liquidity_removable"),
    ("audit", "scam_audit_fake"),
    ("external call", "external_call_unchecked"),
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
    # 🚫 ZERO fallbacku – wymagamy jawnego path=
    path_param = request.args.get("path", "").strip()
    if not path_param:
        return (
            "<p>Brak ścieżki raportu (parametr path jest wymagany).</p>",
            400,
            {"Content-Type": "text/html; charset=utf-8"},
        )

    # zabezpieczenie / sandbox
    abs_path = os.path.abspath(os.path.join(APP_ROOT, path_param))
    if not abs_path.startswith(APP_ROOT):
        return (
            "<p>Nieprawidłowa ścieżka raportu.</p>",
            400,
            {"Content-Type": "text/html; charset=utf-8"},
        )

    if not os.path.isfile(abs_path):
        return (
            f"<p>Brak raportu: {path_param}</p>",
            404,
            {"Content-Type": "text/html; charset=utf-8"},
        )

    # dalszy kod – BEZ ZMIAN
    path = abs_path
    rel = os.path.relpath(path, APP_ROOT)
    ext = os.path.splitext(path)[1].lower()
    ...

    try:
        rel = os.path.relpath(path, APP_ROOT)
        ext = os.path.splitext(path)[1].lower()

        if ext == ".json":
            data = json.load(open(path, "r", encoding="utf-8", errors="ignore"))
            report = (
                data[-1] if isinstance(data, list) and data else (data if isinstance(data, dict) else {})
            )
            name = (
                report.get("identity", {}).get("resolved_name")
                or report.get("name")
                or "Contract"
            )
            addr = report.get("address", "?")
            try:
                score = float(report.get("score", 0.0))
            except Exception:
                score = 0.0

            # decyzja z core (fallback: progi ze score)
            decision = (report.get("decision") or "").upper()
            if not decision:
                if score >= 8.0:
                    decision = "GO"
                elif score >= 6.60:
                    decision = "REVIEW"
                else:
                    decision = "NO-GO"

            badge = _badge_for_decision(decision, score)
            bar_w = max(0, min(100, int((score / 10.0) * 100)))

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

            if decision == "GO":
                desc_block = """
              <div class="desc-go" style="margin-top:6px;margin-bottom:6px;color:#d1fae5;font-size:13px;line-height:1.6;">
                <b>GO — Kod wygląda solidnie.</b><br>
                Kontrakt przeszedł analizy CIS Aurora bez istotnych sygnałów zagrożenia.
                Nie wykryliśmy negatywnych wzorców, blacklist, honeypotów ani ryzykownych konstrukcji.
              </div>"""
            elif decision == "REVIEW":
                desc_block = """
              <div class="desc-review" style="margin-top:6px;margin-bottom:6px;color:#fee2b3;font-size:13px;line-height:1.6;">
                <b>REVIEW — wymagany własny research.</b><br>
                Kod wygląda poprawnie, jednak pewne elementy wymagają dodatkowej weryfikacji manualnej 
                oraz zaufania do zespołu (np. uprawnienia właściciela, duża centralziacja, proxy, zmienne parametry).
                <br>Nie widzimy typowych wzorców scamowych, ale decyzja należy do Ciebie.
              </div>"""
            else:
                desc_block = """
              <div class="desc-nogo" style="margin-top:6px;margin-bottom:6px;color:#fecaca;font-size:13px;line-height:1.6;">
                <b>NO-GO — nie rekomendujemy.</b><br>
                Wykryto wzorce wysokiego ryzyka (np. blacklist, honeypot, manipulacje podatkami,
                niebezpieczne uprawnienia właściciela lub ukryte funkcje).
                <br>Kategorycznie odradzamy interakcję z tym kontraktem — ryzyko utraty środków jest wysokie.
              </div>"""

            # tylko blok opisu decyzji – bez dodatkowego DYOR-bloku
            detected_html = desc_block

            pair_rows = []
            keys = EYES_ORDER[:] if EYES_ORDER else list(EYES_DATA.keys())
            for i in range(0, len(keys), 2):
                pair = keys[i : i + 2]
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

            analyze_html = (
                "<div style='margin-top:16px;margin-bottom:6px;font-weight:700;border-left:4px solid #3b82f6;padding-left:8px'>Co analizujemy (stałe obszary audytu)</div>"
                + "".join(pair_rows)
            )
            return (
                header + detected_html + analyze_html,
                200,
                {"Content-Type": "text/html; charset=utf-8"},
            )

        # TXT fallback (stare raporty)
        txt = open(path, "r", encoding="utf-8", errors="ignore").read()
        item = _parse_first_line_csv(txt) or {
            "name": "?",
            "address": "?",
            "score": "0",
            "label": "RISK",
        }
        name = item.get("name", "?")
        addr = item.get("address", "?")
        try:
            score = float(item.get("score", 0.0))
        except Exception:
            score = 0.0
        badge = _badge_by_score(score)
        bar_w = max(0, min(100, int((score / 10.0) * 100)))

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

        # TXT: bez dodatkowego DYOR-bloku, tylko header + sekcja „Co analizujemy”
        detected_html = ""

        pair_rows = []
        keys = EYES_ORDER[:] if EYES_ORDER else list(EYES_DATA.keys())
        for i in range(0, len(keys), 2):
            pair = keys[i : i + 2]
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

        analyze_html = (
            "<div style='margin-top:16px;margin-bottom:6px;font-weight:700;border-left:4px solid #3b82f6;padding-left:8px'>Co analizujemy (stałe obszary audytu)</div>"
            + "".join(pair_rows)
        )
        return (
            header + detected_html + analyze_html,
            200,
            {"Content-Type": "text/html; charset=utf-8"},
        )

    except Exception as e:
        return (
            f"<pre>{e}</pre>",
            500,
            {"Content-Type": "text/html; charset=utf-8"},
        )


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    app.run(host="0.0.0.0", port=port, debug=False)
#test
