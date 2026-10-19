"""
LedgerWall IDS — mitmproxy Interceptor & Active Blocker (WAF / IPS)
==================================================================
Intercepts HTTP/HTTPS traffic flowing through the reverse proxy (:8080).

Functionality:
  1. Active Prevention (IPS / WAF):
     Inspects request URL, query parameters, and POST bodies.
     If an attack pattern (SQLi, XSS, Path Traversal, Cmd Injection) is matched,
     mitmproxy immediately terminates the request and returns an HTTP 403 Forbidden
     security block page directly to the client browser.
     The backend legacy server (:81) NEVER receives the malicious payload.

  2. Alert Forwarding:
     Forwards the alert metadata with action="BLOCKED" to the IDS engine (:5000)
     via SocketIO so the central dashboard reflects the threat in real time.

  3. Benign Traffic Pass-Through:
     Clean requests pass transparently to http://localhost:81 with minimal latency.
"""

import html
import re
import time
import uuid
from urllib.parse import unquote_plus
import mitmproxy.http
import socketio

# ---------------------------------------------------------------------------
# SocketIO client — persistent connection to the IDS engine
# ---------------------------------------------------------------------------
sio = socketio.Client(reconnection=True, reconnection_delay=2, reconnection_attempts=20)
_connected = False


@sio.event
def connect():
    global _connected
    _connected = True
    print("[MITM] Connected to IDS engine on port 5000")


@sio.event
def disconnect():
    global _connected
    _connected = False
    print("[MITM] Disconnected from IDS engine — will attempt reconnect")


@sio.event
def connect_error(data):
    pass


def _ensure_connected():
    global _connected
    if not _connected:
        try:
            sio.connect("http://localhost:5000", namespaces=["/"])
        except Exception:
            pass


_ensure_connected()

# ---------------------------------------------------------------------------
# Core Attack Signatures for In-Line Active Blocking
# ---------------------------------------------------------------------------
SQLI_PATTERNS = [
    re.compile(r"(?i)(union[\s\+]+select)"),
    re.compile(r"(?i)(select\s+.+\s+from\s+)"),
    re.compile(r"(?i)(insert\s+into\s+)"),
    re.compile(r"(?i)(drop\s+table)"),
    re.compile(r"(?i)(delete\s+from\s+)"),
    re.compile(r"(?i)(update\s+.+\s+set\s+)"),
    re.compile(r"(?i)(\b(or|and)\b[\s\+]+(['\"]?\w+['\"]?)[\s\+]*=[\s\+]*\3)"),
    re.compile(r"(?i)(\b(or|and)\b[\s\+]+['\"]?\d+['\"]?[\s\+]*=[\s\+]*['\"]?\d+)"),
    re.compile(r"(?i)('[\s\+]*(or|and)[\s\+]+)"),
    re.compile(r"(?i)(\d+[\s\+]*=[\s\+]*\d+[\s\+]*(;|--|#))"),
    re.compile(r"(?i)(--|#|/\*.*?\*/)"),
    re.compile(r"(?i)(xp_cmdshell|benchmark\s*\(|sleep\s*\(|information_schema|into\s+outfile)"),
]

XSS_PATTERNS = [
    re.compile(r"(?i)(<script[\s>])"),
    re.compile(r"(?i)(</script>)"),
    re.compile(r"(?i)(javascript\s*:)"),
    re.compile(r"(?i)(on(load|click|mouseover|mouseout|error|focus|blur|change|submit)\s*=)"),
    re.compile(r"(?i)(<\s*iframe[\s>])"),
    re.compile(r"(?i)(<\s*img[^>]+onerror\s*=)"),
    re.compile(r"(?i)(document\s*\.\s*(cookie|write))"),
    re.compile(r"(?i)(alert\s*\()"),
]

PATH_TRAVERSAL_PATTERNS = [
    re.compile(r"(\.\./){2,}"),
    re.compile(r"(%2e%2e%2f){2,}"),
    re.compile(r"(\.\.\\){2,}"),
    re.compile(r"(/etc/passwd|/etc/shadow|/proc/self)"),
    re.compile(r"(?i)(windows[\\/]system32)"),
    re.compile(r"(\.\./\.\./)"),
]

COMMAND_INJECTION_PATTERNS = [
    re.compile(r"(?i)(;\s*(ls|cat|id|whoami|uname|ping|wget|curl|bash|sh)\b)"),
    re.compile(r"(?i)(\|\s*(ls|cat|id|whoami|bash|sh)\b)"),
    re.compile(r"(?i)(`[^`]+`)"),
    re.compile(r"(?i)(\$\([^)]+\))"),
]

BLOCK_RULES = [
    ("SQL Injection (SQLi)", "SQLi", "HIGH", SQLI_PATTERNS),
    ("Cross-Site Scripting (XSS)", "XSS", "MEDIUM", XSS_PATTERNS),
    ("Directory Path Traversal", "PathTraversal", "HIGH", PATH_TRAVERSAL_PATTERNS),
    ("Command Injection", "CmdInjection", "CRITICAL", COMMAND_INJECTION_PATTERNS),
]


def detect_threat(searchable_targets):
    """Returns (threat_name, category, severity, matched_pattern) or None."""
    for threat_name, cat, sev, patterns in BLOCK_RULES:
        for pat in patterns:
            for text in searchable_targets:
                if pat.search(text):
                    return threat_name, cat, sev, pat.pattern
    return None


# ---------------------------------------------------------------------------
# HTML 403 Security Block Page
# ---------------------------------------------------------------------------
BLOCK_PAGE_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>403 Forbidden — Request Blocked</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: #0b0f19;
            color: #f8fafc;
            display: flex;
            align-items: center;
            justify-content: center;
            min-height: 100vh;
            padding: 24px;
        }
        .card {
            max-width: 620px;
            width: 100%;
            background: #111827;
            border: 1px solid #dc2626;
            border-radius: 12px;
            padding: 36px;
            box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.6), 0 0 20px rgba(220, 38, 38, 0.25);
        }
        .badge-blocked {
            display: inline-block;
            background: #dc2626;
            color: #ffffff;
            font-size: 11px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 1px;
            padding: 4px 10px;
            border-radius: 4px;
            margin-bottom: 16px;
        }
        h1 {
            font-size: 22px;
            font-weight: 700;
            color: #ffffff;
            margin-bottom: 10px;
        }
        p {
            color: #94a3b8;
            font-size: 14px;
            line-height: 1.6;
            margin-bottom: 24px;
        }
        .box {
            background: #0f172a;
            border: 1px solid #1f2937;
            border-radius: 8px;
            padding: 16px 20px;
            margin-bottom: 24px;
        }
        .row {
            display: flex;
            justify-content: space-between;
            padding: 8px 0;
            border-bottom: 1px solid #1e293b;
            font-size: 13px;
        }
        .row:last-child { border-bottom: none; }
        .label { color: #64748b; font-weight: 500; }
        .val { color: #f1f5f9; font-family: ui-monospace, Menlo, Consolas, monospace; font-weight: 600; }
        .val-danger { color: #ef4444; }
        .btn {
            display: inline-block;
            background: #2563eb;
            color: #ffffff;
            padding: 10px 22px;
            border-radius: 6px;
            text-decoration: none;
            font-size: 13px;
            font-weight: 600;
            transition: background 0.15s;
        }
        .btn:hover { background: #1d4ed8; }
        .footer {
            margin-top: 24px;
            font-size: 12px;
            color: #475569;
            text-align: center;
        }
    </style>
</head>
<body>
    <div class="card">
        <span class="badge-blocked">Action: Blocked (HTTP 403)</span>
        <h1>Access Denied &mdash; Malicious Request Detected</h1>
        <p>The LedgerWall Intrusion Detection &amp; Prevention System intercepted and blocked this request. The backend audit database was protected and no code was executed.</p>
        
        <div class="box">
            <div class="row">
                <span class="label">Identified Threat</span>
                <span class="val val-danger">__THREAT_TYPE__</span>
            </div>
            <div class="row">
                <span class="label">Action Taken</span>
                <span class="val">BLOCKED (403 Forbidden)</span>
            </div>
            <div class="row">
                <span class="label">Client IP Address</span>
                <span class="val">__CLIENT_IP__</span>
            </div>
            <div class="row">
                <span class="label">Requested URI</span>
                <span class="val">__REQUEST_URL__</span>
            </div>
            <div class="row">
                <span class="label">Incident ID</span>
                <span class="val">__INCIDENT_ID__</span>
            </div>
        </div>

        <a href="/login.php" class="btn">&larr; Return to Clean Portal</a>

        <div class="footer">
            LedgerWall Accounting &amp; Finance &bull; Autonomous Security System
        </div>
    </div>
</body>
</html>
"""


# ---------------------------------------------------------------------------
# Request Interceptor
# ---------------------------------------------------------------------------
def request(flow: mitmproxy.http.HTTPFlow):
    _ensure_connected()

    try:
        # Extract body safely
        raw_content = flow.request.content
        content = raw_content[:4096].decode("utf-8", errors="replace") if raw_content else ""

        # Extract client IP
        client_ip = "127.0.0.1"
        if flow.client_conn and flow.client_conn.address:
            client_ip = flow.client_conn.address[0]
        xff = flow.request.headers.get("X-Forwarded-For", "").strip()
        if xff:
            client_ip = xff.split(",")[0].strip()

        url = flow.request.pretty_url
        raw_target = f"{url} {content}"
        decoded_target = unquote_plus(raw_target)
        double_decoded = unquote_plus(decoded_target)

        # Inspect for threats
        threat_match = detect_threat([raw_target, decoded_target, double_decoded])

        incident_id = uuid.uuid4().hex[:12].upper()

        if threat_match:
            threat_name, category, severity, pat = threat_match
            print(f"[MITM] [ACTION: BLOCKED] {threat_name} from {client_ip} -> {url[:100]} (HTTP 403)")

            # Generate 403 Forbidden response immediately
            resp_body = (
                BLOCK_PAGE_HTML
                .replace("__THREAT_TYPE__", html.escape(threat_name))
                .replace("__CLIENT_IP__", html.escape(client_ip))
                .replace("__REQUEST_URL__", html.escape(url[:120]))
                .replace("__INCIDENT_ID__", incident_id)
            ).encode("utf-8")

            flow.response = mitmproxy.http.Response.make(
                403,
                resp_body,
                {"Content-Type": "text/html; charset=utf-8", "Server": "LedgerWall-IDS-WAF"}
            )

            # Forward alert with action="BLOCKED" to IDS.py
            if _connected:
                sio.emit("request", {
                    "method": flow.request.method,
                    "url": url,
                    "path": flow.request.path,
                    "host": flow.request.host,
                    "headers": dict(flow.request.headers),
                    "content": content,
                    "client_ip": client_ip,
                    "category": category,
                    "severity": severity,
                    "action": "BLOCKED",
                    "incident_id": incident_id,
                    "alert": f"[{category} BLOCKED] {threat_name} from {client_ip} -> {url[:150]}",
                    "timestamp": int(time.time()),
                }, namespace="/")
            return

        # Clean request — forward to backend & emit for traffic accounting
        print(f"[MITM] [ACTION: ALLOWED] {flow.request.method} {url[:80]}")
        if _connected:
            sio.emit("request", {
                "method": flow.request.method,
                "url": url,
                "path": flow.request.path,
                "host": flow.request.host,
                "headers": dict(flow.request.headers),
                "content": content,
                "client_ip": client_ip,
                "action": "ALLOWED",
                "timestamp": int(time.time()),
            }, namespace="/")

    except Exception as e:
        print(f"[MITM] Processing error: {e}")


def done():
    global _connected
    if _connected:
        try:
            sio.disconnect()
        except Exception:
            pass
    print("[MITM] Interceptor shut down")
