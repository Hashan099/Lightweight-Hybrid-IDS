"""
LedgerWall IDS — Automated Security Efficacy & Stress Testing Suite
===================================================================
Replicates the evaluation methodology from Chapter 3 & 4 of the dissertation:
  1. Application-Layer Signature Testing (FR-01)
     Sends the exact 20 attack payloads (SQLi, XSS, Path Traversal) to the proxy
     (default port 8080) or directly to the IDS engine.
  2. DDoS / Volumetric Flood Stress Testing (FR-02)
     Sends rapid bursts of requests within the detection window to verify the
     threshold-based anomaly detection engine triggers.

Usage:
    # Test via reverse proxy (port 8080)
    python simulate_attacks.py --target http://localhost:8080/login.php

    # Direct test to mock app or proxy
    python simulate_attacks.py --all
"""

import argparse
import time
import requests

DISSERTATION_PAYLOADS = [
    # SQL Injections
    {"id": 1, "type": "SQLi", "payload": "admin' OR 1=1"},
    {"id": 2, "type": "SQLi", "payload": "admin\" AND 2=2"},
    {"id": 3, "type": "SQLi", "payload": "UNION SELECT username, password FROM users"},
    {"id": 4, "type": "SQLi", "payload": "SELECT * FROM admin_table"},
    {"id": 5, "type": "SQLi", "payload": "DROP TABLE users"},
    {"id": 6, "type": "SQLi", "payload": "INSERT INTO logs VALUES ('hacker')"},
    {"id": 7, "type": "SQLi", "payload": "UPDATE users SET role='admin'"},
    {"id": 8, "type": "SQLi", "payload": "DELETE FROM accounts"},
    {"id": 9, "type": "SQLi", "payload": "' OR 'a'='a"},
    # XSS Payloads
    {"id": 10, "type": "XSS", "payload": "<script>alert('XSS')</script>"},
    {"id": 11, "type": "XSS", "payload": "<script src='http://evil.com/hook.js'></script>"},
    {"id": 12, "type": "XSS", "payload": "javascript:alert(document.cookie)"},
    {"id": 13, "type": "XSS", "payload": "<body onload=alert('hacked')>"},
    {"id": 14, "type": "XSS", "payload": "<img src=x onerror=alert('hacked')>"},
    # Path Traversal
    {"id": 15, "type": "PathTraversal", "payload": "../../../etc/passwd"},
    {"id": 16, "type": "PathTraversal", "payload": "../../../windows/system32/cmd.exe"},
    {"id": 17, "type": "PathTraversal", "payload": "../etc/passwd"},
    {"id": 18, "type": "PathTraversal", "payload": "../windows/system32/cmd.exe"},
    {"id": 19, "type": "PathTraversal", "payload": "../../../var/log/apache2/access.log"},
    # Advanced Evasion / DOM edge case from dissertation Figure 4.3
    {"id": 20, "type": "XSS", "payload": "<a href='#' onmouseover=alert('bypass')>Hover me</a>"}
]

def test_payloads(target_url):
    print("\n=======================================================")
    print("  LEDGERWALL IDS — APPLICATION LAYER EFFICACY TEST")
    print(f"  Target: {target_url}")
    print("=======================================================")
    print(f"[*] Total Payloads to Test: {len(DISSERTATION_PAYLOADS)}\n")

    sent = 0
    for item in DISSERTATION_PAYLOADS:
        p = item["payload"]
        pid = f"[{item['id']:02d}]"
        
        try:
            # Send payload via GET query param and POST form body
            res = requests.post(
                target_url,
                data={"username": p, "password": "dummy_password"},
                params={"query": p},
                timeout=3
            )
            print(f"{pid} SENT -> {p[:60]}")
            sent += 1
            time.sleep(0.15)
        except Exception as e:
            print(f"{pid} Failed to connect: {e}")
            break

    print("\n=======================================================")
    print(f"  Delivered {sent} attack payloads to proxy.")
    print("  Check your live dashboard at http://localhost:5000")
    print("  Look at the 'Detection Log' and 'Overview' charts!")
    print("=======================================================\n")

def test_ddos_flood(target_url, count=35):
    print("\n=======================================================")
    print("  LEDGERWALL IDS — APPLICATION LAYER DDOS SIMULATION")
    print(f"  Sending {count} high-velocity requests to test threshold...")
    print("=======================================================")

    success = 0
    start = time.time()
    for i in range(1, count + 1):
        try:
            requests.get(target_url, timeout=2)
            success += 1
            print(f"[*] Packet #{i:02d} dispatched...")
        except Exception:
            pass
        time.sleep(0.05) # fast burst within 2 seconds

    duration = round(time.time() - start, 2)
    print(f"\n[OK] Sent {success} requests in {duration}s.")
    print("Threshold in config is 30 req/10s -> Check dashboard for [DDoS ALERT]!")
    print("=======================================================\n")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="IDS Security Test Suite")
    parser.add_argument("--target", default="http://localhost:8080/login.php", help="Target URL (e.g. proxy on 8080)")
    parser.add_argument("--ddos", action="store_true", help="Run DDoS burst flood test only")
    parser.add_argument("--all", action="store_true", help="Run both signature and DDoS test")
    args = parser.parse_args()

    if args.ddos:
        test_ddos_flood(args.target)
    elif args.all:
        test_payloads(args.target)
        time.sleep(1)
        test_ddos_flood(args.target)
    else:
        test_payloads(args.target)
