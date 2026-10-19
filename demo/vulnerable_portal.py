"""
LedgerWall Accounting & Finance — Mock Legacy Audit Web Portal
=============================================================
Simulates the firm's legacy LAMP-stack application running on port 81.
Provides sample endpoints (login.php, audit.php, ledger.php) for testing
traffic forwarded through the mitmproxy reverse proxy.

Run with:
    python mock_legacy_app.py
    (or via start.bat / automated test suite)
"""

from flask import Flask, request, jsonify, render_template_string

app = Flask(__name__)

HTML_PORTAL = """
<!DOCTYPE html>
<html>
<head>
    <title>LedgerWall Audit Portal (Legacy System)</title>
    <style>
        body { font-family: Arial, sans-serif; background: #f0f2f5; margin: 40px; color: #333; }
        .card { background: white; padding: 30px; border-radius: 8px; max-width: 600px; margin: auto; box-shadow: 0 4px 12px rgba(0,0,0,0.1); }
        h2 { color: #1e3a8a; }
        input[type="text"], input[type="password"] { width: 100%; padding: 10px; margin: 10px 0; border: 1px solid #ccc; border-radius: 4px; box-sizing: border-box; }
        button { background: #2563eb; color: white; padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; }
        button:hover { background: #1d4ed8; }
        .badge { background: #fee2e2; color: #b91c1c; padding: 4px 8px; border-radius: 4px; font-size: 12px; }
        .success { background: #dcfce7; color: #15803d; }
    </style>
</head>
<body>
    <div class="card">
        <h2>LedgerWall Accounting &amp; Finance</h2>
        <p><span class="badge">Legacy Internal Audit Portal (v2.4 - PHP 5.6 Simulation)</span></p>
        <hr/>
        <div style="background:#f1f5f9;border:1px solid #cbd5e1;padding:8px 12px;border-radius:4px;margin-bottom:15px;font-size:12px;">
            <strong>Traffic Source:</strong> <code>http://{{ request_host }}</code>
            {% if "8080" in request_host %}
                <span style="color:#15803d;font-weight:bold;">&check; Routed through IDS Proxy (Monitored)</span>
            {% else %}
                <span style="color:#b91c1c;font-weight:bold;">&cross; Direct Server Access (Bypasses IDS! Use <a href="http://localhost:8080/login.php">http://localhost:8080/login.php</a>)</span>
            {% endif %}
        </div>
        <form method="POST" action="login.php">
            <label>Auditor Username:</label>
            <input type="text" name="username" placeholder="e.g. auditor_01 or admin' OR 1=1--" required />
            <label>Password:</label>
            <input type="password" name="password" placeholder="••••••••" required />
            <button type="submit">Sign In to Audit Ledger</button>
        </form>
    </div>
</body>
</html>
"""

@app.route("/", methods=["GET"])
@app.route("/login.php", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        user = request.form.get("username", "")
        return f"""
        <html><body style="font-family:Arial;padding:40px;">
        <h3>Login Response (Legacy App)</h3>
        <p>Received user: <code>{user}</code></p>
        <p><a href="login.php">&larr; Back to Portal</a></p>
        </body></html>
        """
    return render_template_string(HTML_PORTAL, request_host=request.host)

@app.route("/ledger.php", methods=["GET"])
def ledger():
    query = request.args.get("q", "default")
    return jsonify({
        "status": "success",
        "firm": "LedgerWall Accounting & Finance",
        "query": query,
        "sample_records": [
            {"client": "Apex Logistics Ltd", "audit_year": 2025, "balance_lkr": 4500000.00},
            {"client": "Gampaha Exports", "audit_year": 2025, "balance_lkr": 12800000.50}
        ]
    })

if __name__ == "__main__":
    print("[MOCK APP] Starting legacy firm audit app on http://127.0.0.1:81 ...")
    app.run(host="127.0.0.1", port=81, debug=False)
