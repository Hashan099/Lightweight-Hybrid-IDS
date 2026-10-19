"""
LedgerWall Lightweight IDS — Core Engine
=========================================
Flask + SocketIO backend.

Database backend is selected automatically at startup by db.py:
  - MongoDB (production) if reachable on MONGO_URI
  - JSON files  (local dev)  otherwise — no installation required

Detection layers:
  1. Built-in regex signatures  — SQLi, XSS, Path Traversal, Cmd Injection
  2. User-defined MongoDB/JSON rules — stored and managed via the dashboard
  3. Application-layer DDoS — per-IP HTTP request rate threshold
  4. Network-layer DDoS — via scapy_monitor.py feeding packet_event over SocketIO
"""

from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO, emit
from datetime import datetime
from collections import defaultdict
import re
import threading
import time
import pytz

# ---------------------------------------------------------------------------
# Storage layer (auto-selects MongoDB or JSON fallback)
# ---------------------------------------------------------------------------
from database import db

# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------
app = Flask(__name__)
app.config["SECRET_KEY"] = "ledgerwall-ids-secret-2026"

socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

TIMEZONE = pytz.timezone("Asia/Colombo")

# ---------------------------------------------------------------------------
# In-memory tracking (reset on restart — intentional for lightweight design)
# ---------------------------------------------------------------------------
ddos_tracker:     dict[str, list[float]] = defaultdict(list)
ddos_last_alert:  dict[str, float]       = {}
ip_alert_counts:  dict[str, int]         = defaultdict(int)
ip_blocklist:     set[str]               = set()
packet_tracker:   dict[str, list[float]] = defaultdict(list)
packet_last_alert: dict[str, float]      = {}

START_TIME = time.time()

# ---------------------------------------------------------------------------
# Live configuration (editable at runtime via /api/config)
# ---------------------------------------------------------------------------
config = {
    "DDOS_TIME_WINDOW":    10,
    "DDOS_THRESHOLD":      30,
    "DDOS_ALERT_COOLDOWN": 10,
    "PACKET_TIME_WINDOW":   5,
    "PACKET_THRESHOLD":   500,
    "PACKET_ALERT_COOLDOWN": 15,
    "BLOCKLIST_THRESHOLD": 10,
    "BLOCKLIST_ENABLED":  True,
}

# ---------------------------------------------------------------------------
# Attack signature patterns
# ---------------------------------------------------------------------------
SQLI_PATTERNS = [
    r"(?i)(union[\s\+]+select)",
    r"(?i)(select\s+.+\s+from\s+)",
    r"(?i)(insert\s+into\s+)",
    r"(?i)(drop\s+table)",
    r"(?i)(delete\s+from\s+)",
    r"(?i)(update\s+.+\s+set\s+)",
    r"(?i)(exec(\s|\+)+(s|x)p\w+)",
    r"(?i)(\b(or|and)\b[\s\+]+(['\"]?\w+['\"]?)[\s\+]*=[\s\+]*\3)",
    r"(?i)(\b(or|and)\b[\s\+]+['\"]?\d+['\"]?[\s\+]*=[\s\+]*['\"]?\d+)",
    r"(?i)('[\s\+]*(or|and)[\s\+]+)",
    r"(?i)(\d+[\s\+]*=[\s\+]*\d+[\s\+]*(;|--|#))",
    r"(?i)(--|#|/\*.*?\*/)",
    r"(?i)(xp_cmdshell)",
    r"(?i)(benchmark\s*\()",
    r"(?i)(sleep\s*\()",
    r"(?i)(waitfor\s+delay)",
    r"(?i)(';\s*(drop|delete|insert|update|create|alter))",
    r"(?i)(information_schema)",
    r"(?i)(load_file\s*\()",
    r"(?i)(into\s+outfile)",
]

XSS_PATTERNS = [
    r"(?i)(<script[\s>])",
    r"(?i)(</script>)",
    r"(?i)(javascript\s*:)",
    r"(?i)(on(load|click|mouseover|mouseout|error|focus|blur|change|submit|reset|keydown|keyup|keypress)\s*=)",
    r"(?i)(<\s*iframe[\s>])",
    r"(?i)(<\s*img[^>]+onerror\s*=)",
    r"(?i)(document\s*\.\s*cookie)",
    r"(?i)(document\s*\.\s*write\s*\()",
    r"(?i)(eval\s*\()",
    r"(?i)(alert\s*\()",
    r"(?i)(<\s*object[\s>])",
    r"(?i)(<\s*embed[\s>])",
    r"(?i)(expression\s*\()",
    r"(?i)(vbscript\s*:)",
    r"(?i)(data\s*:\s*text/html)",
]

PATH_TRAVERSAL_PATTERNS = [
    r"(\.\./){2,}",
    r"(%2e%2e%2f){2,}",
    r"(%252e%252e%252f)",
    r"(\.\.\\){2,}",
    r"(/etc/passwd)",
    r"(/etc/shadow)",
    r"(/proc/self)",
    r"(?i)(c:\\windows\\system32)",
    r"(%00\.\.)",
    r"(\.\./\.\./\.\./)",
]

COMMAND_INJECTION_PATTERNS = [
    r"(?i)(;\s*(ls|cat|id|whoami|uname|ping|wget|curl|bash|sh)\b)",
    r"(?i)(\|\s*(ls|cat|id|whoami|bash|sh)\b)",
    r"(?i)(`[^`]+`)",
    r"(?i)(\$\([^)]+\))",
]

SIGNATURE_SETS = [
    {"patterns": [re.compile(p) for p in SQLI_PATTERNS],             "category": "SQLi",          "severity": "HIGH",     "alert_prefix": "[SQLi DETECTED]"},
    {"patterns": [re.compile(p) for p in XSS_PATTERNS],              "category": "XSS",           "severity": "MEDIUM",   "alert_prefix": "[XSS DETECTED]"},
    {"patterns": [re.compile(p) for p in PATH_TRAVERSAL_PATTERNS],   "category": "PathTraversal", "severity": "HIGH",     "alert_prefix": "[PATH TRAVERSAL DETECTED]"},
    {"patterns": [re.compile(p) for p in COMMAND_INJECTION_PATTERNS],"category": "CmdInjection",  "severity": "CRITICAL", "alert_prefix": "[COMMAND INJECTION DETECTED]"},
]

# ---------------------------------------------------------------------------
# In-memory rules cache
# ---------------------------------------------------------------------------
rules_cache: list[dict] = []
rules_lock = threading.Lock()


def load_rules():
    with rules_lock:
        global rules_cache
        rules_cache = db.get_rules()
    print(f"[IDS] Rules loaded: {len(rules_cache)}")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _now_iso() -> str:
    return datetime.now(TIMEZONE).isoformat()


def _now_ts() -> int:
    return int(time.time())


def _uptime_seconds() -> int:
    return int(time.time() - START_TIME)


def _check_blocklist(ip: str) -> bool:
    return config["BLOCKLIST_ENABLED"] and ip in ip_blocklist


def _record_alert_for_ip(ip: str):
    ip_alert_counts[ip] += 1
    if config["BLOCKLIST_ENABLED"] and ip_alert_counts[ip] >= config["BLOCKLIST_THRESHOLD"]:
        if ip not in ip_blocklist:
            ip_blocklist.add(ip)
            _save_alert(
                ip=ip, method="SYSTEM", url="N/A", host="N/A",
                category="Blocklist", severity="CRITICAL",
                alert=f"[AUTO-BLOCKED] IP {ip} auto-blocked after {ip_alert_counts[ip]} alerts",
                headers={}, content="",
            )


def _save_alert(ip, method, url, host, category, severity, alert, headers, content, action="BLOCKED"):
    """Persist to DB and push to dashboard clients."""
    log_entry = {
        "timestamp": _now_ts(),
        "date":      _now_iso(),
        "method":    method,
        "url":       url,
        "host":      host,
        "ip":        ip,
        "headers":   headers,
        "content":   content[:512] if content else "",
        "category":  category,
        "severity":  severity,
        "alert":     alert,
        "action":    action,
    }
    db.insert_alert(log_entry)
    print(f"[{action}] [{severity}] {category}: {alert}")

    payload = {
        "alert":    alert,
        "category": category,
        "severity": severity,
        "ip":       ip,
        "method":   method,
        "url":      url,
        "action":   action,
        "date":     log_entry["date"],
    }
    socketio.emit("new_alert",    payload,           namespace="/web")
    socketio.emit("stats_update", _compute_stats(),  namespace="/web")


# ---------------------------------------------------------------------------
# Detection functions
# ---------------------------------------------------------------------------

def check_signatures(data: dict):
    from urllib.parse import urlparse, unquote_plus
    ip  = data.get("client_ip", "unknown")
    url = data.get("url", "")
    content = data.get("content", "")
    parsed_url = urlparse(url)

    # Check both raw and URL-decoded forms (and double-decoded for evasion)
    raw_str = f"{url} {content}"
    decoded_str = unquote_plus(raw_str)
    double_decoded = unquote_plus(decoded_str)
    targets = [raw_str, decoded_str, double_decoded]

    for sig_set in SIGNATURE_SETS:
        matched = False
        for pattern in sig_set["patterns"]:
            for t in targets:
                if pattern.search(t):
                    alert_msg = f"{sig_set['alert_prefix']} from {ip} -> {url[:200]}"
                    _save_alert(
                        ip=ip, method=data.get("method", ""),
                        url=url, host=parsed_url.hostname or "",
                        category=sig_set["category"], severity=sig_set["severity"],
                        alert=alert_msg, headers=data.get("headers", {}), content=content,
                    )
                    _record_alert_for_ip(ip)
                    matched = True
                    break
            if matched:
                break


def check_custom_rules(data: dict):
    from urllib.parse import urlparse, unquote_plus
    ip = data.get("client_ip", "unknown")

    with rules_lock:
        current_rules = list(rules_cache)

    for rule in current_rules:
        flag = True
        for key, value in rule.items():
            if key in ["alert", "headers", "_id", "category", "severity", "created_at"]:
                continue
            if key not in data:
                flag = False
                break

            field_raw = str(data[key]).lower()
            field_unquoted = unquote_plus(str(data[key])).lower()
            val_lower = str(value).lower()
            if val_lower not in field_raw and val_lower not in field_unquoted:
                flag = False
                break

        if flag and "headers" in rule:
            req_headers = {k.lower(): str(v).lower() for k, v in data.get("headers", {}).items()}
            for hkey, hval in rule["headers"].items():
                target_header = req_headers.get(hkey.lower(), "")
                if str(hval).lower() not in target_header:
                    flag = False
                    break

        if flag:
            parsed_url = urlparse(data.get("url", ""))
            _save_alert(
                ip=ip, method=data.get("method", ""),
                url=data.get("url", ""), host=parsed_url.hostname or "",
                category=rule.get("category", "Custom"),
                severity=rule.get("severity", "MEDIUM"),
                alert=rule.get("alert", "Custom rule alert"),
                headers=data.get("headers", {}), content=data.get("content", ""),
            )
            _record_alert_for_ip(ip)


def check_app_ddos(data: dict) -> bool:
    from urllib.parse import urlparse
    ip      = data.get("client_ip", "unknown")
    now     = time.time()
    window  = config["DDOS_TIME_WINDOW"]
    thresh  = config["DDOS_THRESHOLD"]
    cooldown = config["DDOS_ALERT_COOLDOWN"]

    ddos_tracker[ip].append(now)
    ddos_tracker[ip] = [t for t in ddos_tracker[ip] if now - t <= window]

    if len(ddos_tracker[ip]) > thresh:
        if ip not in ddos_last_alert or (now - ddos_last_alert[ip]) > cooldown:
            ddos_last_alert[ip] = now
            parsed_url = urlparse(data.get("url", ""))
            alert_msg = (
                f"[DDoS ALERT] {len(ddos_tracker[ip])} requests in {window}s from IP: {ip}"
            )
            _save_alert(
                ip=ip, method=data.get("method", ""),
                url=data.get("url", ""), host=parsed_url.hostname or "",
                category="DDoS", severity="CRITICAL",
                alert=alert_msg, headers=data.get("headers", {}), content="",
            )
            _record_alert_for_ip(ip)
            return True
    return False


def _compute_stats() -> dict:
    stats = db.compute_stats()
    stats["uptime_seconds"]  = _uptime_seconds()
    stats["blocked_ips"]     = list(ip_blocklist)
    stats["alerts_per_min"]  = stats.get("alerts_per_min", 0)
    stats["backend"]         = db.backend_name
    return stats


# ---------------------------------------------------------------------------
# SocketIO events
# ---------------------------------------------------------------------------

@socketio.on("connect", namespace="/")
def on_proxy_connect():
    print("[IDS] Proxy / Scapy monitor connected")


@socketio.on("connect", namespace="/web")
def on_web_connect():
    print("[IDS] Dashboard client connected")
    emit("stats_update", _compute_stats())


@socketio.on("request", namespace="/")
def handle_http_request(data: dict):
    data = dict(data)
    ip = data.get("client_ip", "unknown")
    if _check_blocklist(ip):
        return

    # If mitmproxy in-line active filter already blocked it:
    if data.get("action") == "BLOCKED" and data.get("alert"):
        _save_alert(
            ip=ip,
            method=data.get("method", ""),
            url=data.get("url", ""),
            host=data.get("host", ""),
            category=data.get("category", "Threat"),
            severity=data.get("severity", "HIGH"),
            alert=data.get("alert"),
            action="BLOCKED",
            headers=data.get("headers", {}),
            content=data.get("content", ""),
        )
        _record_alert_for_ip(ip)
        return

    check_app_ddos(data)
    check_signatures(data)
    check_custom_rules(data)


@socketio.on("packet_event", namespace="/")
def handle_packet_event(data: dict):
    data  = dict(data)
    ip    = data.get("src_ip", "unknown")
    proto = data.get("proto", "UNKNOWN")
    pps   = data.get("pps", 0)
    now   = time.time()

    key = f"{ip}_{proto}"
    packet_tracker[key].append(now)
    packet_tracker[key] = [
        t for t in packet_tracker[key]
        if now - t <= config["PACKET_TIME_WINDOW"]
    ]

    if len(packet_tracker[key]) > config["PACKET_THRESHOLD"]:
        cooldown = config["PACKET_ALERT_COOLDOWN"]
        if key not in packet_last_alert or (now - packet_last_alert[key]) > cooldown:
            packet_last_alert[key] = now
            alert_msg = (
                f"[NETWORK DDoS] {proto} flood from {ip} — "
                f"{pps} pkt/s exceeds threshold"
            )
            _save_alert(
                ip=ip, method=f"PACKET/{proto}", url="N/A", host="N/A",
                category="NetworkDDoS", severity="CRITICAL",
                alert=alert_msg, headers={}, content="",
            )
            _record_alert_for_ip(ip)


# ---------------------------------------------------------------------------
# REST API — Alerts
# ---------------------------------------------------------------------------

@app.route("/get-logs")
def get_logs():
    """Legacy endpoint (backward compat)."""
    result = db.get_alerts(page=1, limit=500)
    logs = result["alerts"]
    return jsonify(logs or ["No logs found."])


@app.route("/api/alerts")
def api_alerts():
    page     = max(int(request.args.get("page",  1)),   1)
    limit    = min(int(request.args.get("limit", 50)), 200)
    category = request.args.get("category") or None
    severity = request.args.get("severity") or None
    ip       = request.args.get("ip")       or None
    return jsonify(db.get_alerts(page=page, limit=limit, category=category, severity=severity, ip=ip))


@app.route("/api/reset-logs", methods=["POST"])
def api_reset_logs():
    count = db.delete_all_alerts()
    ddos_tracker.clear()
    ddos_last_alert.clear()
    ip_alert_counts.clear()
    ip_blocklist.clear()
    packet_tracker.clear()
    packet_last_alert.clear()
    return jsonify({"status": "success", "message": f"Deleted {count} logs and reset all trackers."})


# ---------------------------------------------------------------------------
# REST API — Stats & System
# ---------------------------------------------------------------------------

@app.route("/api/stats")
def api_stats():
    return jsonify(_compute_stats())


@app.route("/api/system")
def api_system():
    try:
        import psutil
        proc    = psutil.Process()
        mem_mb  = round(proc.memory_info().rss / (1024 * 1024), 2)
        cpu_pct = round(proc.cpu_percent(interval=0.1), 2)
    except ImportError:
        mem_mb  = -1
        cpu_pct = -1

    return jsonify({
        "uptime_seconds":    _uptime_seconds(),
        "memory_mb":         mem_mb,
        "cpu_percent":       cpu_pct,
        "blocked_ips_count": len(ip_blocklist),
        "blocked_ips":       list(ip_blocklist),
        "rules_count":       len(rules_cache),
        "backend":           db.backend_name,
        "backend_info":      db.backend_info,
    })


# ---------------------------------------------------------------------------
# REST API — Rules
# ---------------------------------------------------------------------------

@app.route("/api/get-rules")
def api_get_rules():
    return jsonify(db.get_rules())


@app.route("/api/add-rule", methods=["POST"])
def api_add_rule():
    new_rule = request.get_json()
    if not isinstance(new_rule, dict):
        return jsonify({"status": "error", "message": "Invalid rule data"}), 400
    inserted_id = db.insert_rule(new_rule)
    load_rules()
    return jsonify({"status": "success", "message": "Rule added", "id": inserted_id})


@app.route("/api/update-rule", methods=["POST"])
def api_update_rule():
    data     = request.get_json()
    rule_id  = data.get("id")
    updated  = data.get("updated")
    if not rule_id or not updated:
        return jsonify({"status": "error", "message": "Invalid request data"}), 400
    if db.update_rule(str(rule_id), updated):
        load_rules()
        return jsonify({"status": "success", "message": "Rule updated"})
    return jsonify({"status": "error", "message": "No changes made or rule not found"}), 400


@app.route("/api/delete-rule", methods=["POST"])
def api_delete_rule():
    data    = request.get_json()
    rule_id = data.get("id")
    if not rule_id:
        return jsonify({"status": "error", "message": "Invalid request data"}), 400
    if db.delete_rule(str(rule_id)):
        load_rules()
        return jsonify({"status": "success", "message": "Rule deleted"})
    return jsonify({"status": "error", "message": "Rule not found"}), 400


# ---------------------------------------------------------------------------
# REST API — Blocklist
# ---------------------------------------------------------------------------

@app.route("/api/blocklist")
def api_blocklist():
    return jsonify({"blocked_ips": list(ip_blocklist)})


@app.route("/api/blocklist/add", methods=["POST"])
def api_blocklist_add():
    ip = (request.get_json() or {}).get("ip", "").strip()
    if not ip:
        return jsonify({"status": "error", "message": "IP required"}), 400
    ip_blocklist.add(ip)
    return jsonify({"status": "success", "message": f"{ip} added to blocklist"})


@app.route("/api/blocklist/remove", methods=["POST"])
def api_blocklist_remove():
    ip = (request.get_json() or {}).get("ip", "").strip()
    ip_blocklist.discard(ip)
    ip_alert_counts.pop(ip, None)
    return jsonify({"status": "success", "message": f"{ip} removed from blocklist"})


# ---------------------------------------------------------------------------
# REST API — Configuration
# ---------------------------------------------------------------------------

@app.route("/api/config", methods=["GET"])
def api_config_get():
    return jsonify(config)


@app.route("/api/config", methods=["POST"])
def api_config_set():
    data    = request.get_json() or {}
    updated = {}
    for k, v in data.items():
        if k in config:
            config[k] = v
            updated[k] = v
    return jsonify({"status": "success", "updated": updated})


# ---------------------------------------------------------------------------
# Main route
# ---------------------------------------------------------------------------

@app.route("/")
def home():
    return render_template("index.html")


# ---------------------------------------------------------------------------
# Startup
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print(f"[IDS] Database backend : {db.backend_name.upper()} ({db.backend_info})")
    print("[IDS] Loading rules...")
    load_rules()
    print("[IDS] Starting LedgerWall IDS Engine...")
    print("[IDS] -> Dashboard URL: http://localhost:5000 (or http://127.0.0.1:5000)")
    print("[IDS] -> (Do not use 0.0.0.0 in browser, use localhost:5000)")
    socketio.run(app, host="0.0.0.0", port=5000, debug=False, allow_unsafe_werkzeug=True)
