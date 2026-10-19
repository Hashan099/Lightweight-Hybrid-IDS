# Lightweight Intrusion Detection & Prevention System (IDS/IPS)

[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Framework-Flask%20%7C%20Socket.IO-black.svg)](https://flask.palletsprojects.com/)
[![mitmproxy](https://img.shields.io/badge/WAF%20Engine-mitmproxy%20v10%2B-red.svg)](https://mitmproxy.org/)
[![Scapy](https://img.shields.io/badge/Network%20Sniffer-Scapy%20v2.5%2B-orange.svg)](https://scapy.net/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Academic Dissertation](https://img.shields.io/badge/Dissertation-Cardiff%20Metropolitan%20University-blueviolet.svg)](#-academic-dissertation-context)

> **BSc (Hons) Business Information Systems — Final Year Dissertation Project**  
> **Cardiff Metropolitan University (UK) &bull; Cardiff School of Technology**  
> *In collaboration with ICBT Campus, Sri Lanka*  

---

<img width="2538" height="1300" alt="Screenshot 2026-10-19 182320" src="https://github.com/user-attachments/assets/079e7db7-ccb4-4287-adf1-455339cdc5f2" />
<img width="665" height="595" alt="Screenshot 2026-10-19 182357" src="https://github.com/user-attachments/assets/b8395932-b047-4967-a9dd-1911e28c2c3e" />



## 🎓 Academic Dissertation Context

This software artifact was designed, developed, and empirically evaluated as the capstone research project for the degree of **Bachelor of Science (Honours) in Business Information Systems (BSc BIS)** at **Cardiff Metropolitan University (UK)** in partnership with **ICBT Campus (Sri Lanka)**.

- **Author:** H.I. Gunathilake
- **Academic Year / Submission:** March 2026
- **Research Methodology:** Design Science Research (DSR)
- **Case Study Organization:** LedgerWall Accounting & Finance (Gampaha, Sri Lanka)

---

## 🎯 The Core Philosophy: "Run-On-Anything" Lightweight Security

### What This Project IS NOT:
* **It is NOT an over-engineered AI/Deep-Learning model:** Modern academic literature often proposes Deep Neural Networks (DNNs) or recurrent models for intrusion detection. However, in low-resource environments, such models introduce prohibitive processing latency (often hundreds of milliseconds per transaction) and demand specialized hardware (GPUs/TPUs) or gigabytes of memory that small accounting firms simply cannot afford.
* **It is NOT a bloated enterprise agent:** Industry-standard signature systems such as Snort or Suricata maintain massive state tables and deep packet inspection buffers for thousands of non-essential protocols. Empirical studies demonstrate that running Snort with full commercial rule packs can degrade low-spec server throughput by up to **40%**, exhausting server RAM and crashing the underlying business software.
* **It is NOT an expensive cloud WAF:** Commercial managed cloud firewalls (e.g., Cloudflare Enterprise, AWS WAF) require recurring subscription fees that violate the strict "zero-cost" budget constraints of local SMEs.

### What This Project IS:
* **A pragmatic, run-on-anything security wrapper:** Engineered specifically to resolve the **"Security-Resource Paradox"** faced by SMEs in developing economies.
* **Virtually zero footprint:** Consumes only **~67 MB to 142 MB of RAM** under live attack conditions—running safely inside a fraction of a 2 GB Virtual Private Server (VPS) where legacy MySQL and Apache already consume over 1.2 GB.
* **Microsecond inspection latency:** Introduces an average Time-to-First-Byte (TTFB) overhead of just **4.419 milliseconds**, remaining completely invisible to remote field auditors under statutory deadlines.
* **Virtual Patching without code modification:** Protects fragile, unmaintained legacy PHP 5.6 web portals against modern SQL Injections and XSS attacks without requiring hazardous refactoring of old application code.
* **Zero Software Licensing Cost:** Built 100% on free, open-source building blocks (Python, Flask, mitmproxy, Scapy, Chart.js).
* **Sustainable Computing:** Contributes to **Green Computing** and **Sustainable IT** by extending the safe operational lifespan of older hardware assets, directly reducing electronic waste.

---

## ⚖️ The Problem: The SME Security-Resource Paradox

Financial audit firms handle highly confidential corporate ledgers, tax filings, and payroll databases. In Sri Lanka, such data is strictly governed by the **Personal Data Protection Act No. 9 of 2022**.

At **LedgerWall Accounting & Finance (Gampaha, Sri Lanka)**, field auditors require remote web access to client ledgers via a custom legacy LAMP portal (Linux, Apache, MySQL, PHP 5.6). Due to macroeconomic constraints, migrating to an enterprise SaaS ERP is unfeasible in the short term. The server environment is severely restricted:
- **CPU:** 1 vCPU
- **Total RAM:** 2.0 GB (with MySQL and Apache already consuming ~1.2 GB)
- **Remaining Memory Headroom:** Less than 500 MB (Hard Non-Functional Requirement)
- **Threat Landscape:** Automated SQL Injection bot scraping, directory traversal scans, and volumetric traffic spikes (DDoS) during tax audit deadlines.

Standard enterprise security tools crash this server by inducing Out-Of-Memory (OOM) panics. **LedgerWall IDS** was engineered as the purpose-built solution.

---

## 🏛️ System Architecture

The solution operates as a **hybrid, dual-tier intrusion detection and prevention wrapper**:

### Component Breakdown

| Module | Component | Technical Role |
|---|---|---|
| **`proxy_interceptor.py`** | In-Line WAF / IPS | Reverse proxy addon for `mitmproxy` listening on port `8080`. Inspects request URIs, query strings, headers, and form-urlencoded POST bodies. Automatically decodes multi-level URL encoding (`unquote_plus`) to defeat evasion techniques. If malicious patterns are matched, it **terminates the connection immediately with HTTP 403 Forbidden**, shielding backend port `81`. |
| **`ids_engine.py`** | Core IDS & Analytics Engine | Flask + Socket.IO backend on port `5000`. Runs native Python multi-threading (`async_mode="threading"`). Tracks per-IP request frequency inside a sliding window (`30 req / 10s`) for application DDoS detection, manages dynamic IP blocklists, and serves the REST API. |
| **`network_monitor.py`** | Network-Layer Sniffer | Scapy raw socket sniffer designed for Linux/Windows promiscuous packet capture. Tracks arrival rates of TCP SYN-only packets, UDP datagrams, and ICMP echo floods to mitigate volumetric infrastructure attacks. |
| **`database.py`** | Dual-Mode Storage Engine | Transparent database abstraction layer. Auto-detects MongoDB availability at startup with a 1.5s timeout. If MongoDB is absent, it gracefully switches to local thread-safe JSON files (`./data/`). Auto-initializes with 33+ baseline security rules out of the box. |
| **`templates/index.html`** | High-Legibility Dashboard | Self-contained, high-contrast Dark Slate frontend (`#0b0f19` / `#111827`). Powered by Bootstrap 5, Chart.js, and Socket.IO. Displays real-time threat radar status, live event streams with `BLOCKED` badges, paginated audit logs, and dynamic configuration panels. |
| **`demo/`** | Verification Testbed | Standalone test environment containing `vulnerable_portal.py` (simulating the legacy audit app) and `simulate_attacks.py` (reproducing the dissertation's 20-payload benchmark test). |

---

## 📊 Dissertation Empirical Evaluation & Benchmarks

The IDS artifact was rigorously benchmarked within a native Linux kernel testbed (WSL2 Ubuntu) matching the production VPS specifications. All predefined organizational requirements were met or exceeded:

### 1. Quantitative Performance Metrics

```
Memory Footprint:
  Allowable Budget (NFR-01) : 500.00 MB
  IDS Peak RAM Under Stress  : 142.04 MB  [████████░░░░░░░░░░░░░░░░░░]  28.4% Used  (PASS)

Operational Latency Overhead:
  Allowable Threshold (NFR-02) : 200.00 ms
  Direct Server Baseline        :   2.269 ms
  Proxied via IDS WAF           :   6.688 ms
  Net Added Inspection Latency  :   4.419 ms  [█░░░░░░░░░░░░░░░░░░░░░░░░]   2.2% Ceiling (PASS)

Detection Accuracy:
  Application Layer (FR-01)    :  95.00% (19 of 20 deterministic attack vectors blocked)
  Network DDoS Flood (FR-02)   : 100.00% (Tripped precisely at configured packet threshold)
```

## 🛡️ Comprehensive Detection Vector Matrix

### Application Layer (In-Line WAF via `proxy_interceptor.py`)
| Threat Category | Primary Target | Detection Technique & Regex Patterns | Action |
|---|---|---|---|
| **SQL Injection (SQLi)** | Login forms, URL params, audit search | 19 compiled regexes detecting `UNION SELECT`, `DROP TABLE`, boolean tautologies (`'a'='a'`, `1=1`), inline comments (`--`, `#`, `/*`), time-based delay injection (`sleep()`, `benchmark()`), and administrative extraction (`information_schema`, `into outfile`). | **HTTP 403 BLOCKED** |
| **Cross-Site Scripting (XSS)** | Form inputs, reflected queries | 15 patterns detecting `<script>`, pseudo-protocols (`javascript:`), DOM event attributes (`onerror=`, `onload=`, `onmouseover=`, `onclick=`), `document.cookie` extraction. | **HTTP 403 BLOCKED** |
| **Directory Traversal** | File download & view routes | 10 patterns detecting directory climbing (`../`, `..\`), double URL encoding (`%252e%252e%252f`), sensitive targets (`/etc/passwd`, `/etc/shadow`, Windows system paths). | **HTTP 403 BLOCKED** |
| **Command Injection** | Operating system subshells | Shell metacharacters (`;`, `\|`, backticks, `$()`, system commands `cat`, `whoami`, `bash`). | **HTTP 403 BLOCKED** |
| **Automated Scanners** | HTTP Request Headers | User-Agent signature fingerprinting for automated penetration tools: `sqlmap`, `nikto`, `nmap`, `masscan`, `dirbuster`, `gobuster`. | **HTTP 403 BLOCKED** |
| **Endpoint Probing** | Web server root | Direct access attempts to sensitive administrative endpoints: `/.env`, `/.git`, `/phpMyAdmin`, `/wp-admin`, web shells (`/shell`, `/cmd`). | **HTTP 403 BLOCKED** |

### Network & Volumetric Layer (Anomaly Thresholding)
| Threat Category | Layer | Mechanism & Trigger Threshold | Action |
|---|---|---|---|
| **HTTP Request Flood (L7 DDoS)** | Application (L7) | Sliding time-window tracking in `ids_engine.py`. Trigger: `> 30 requests within 10 seconds` from a single IP. | **DDoS ALERT & Auto-Blocklist** |
| **TCP SYN Flood** | Network (L4) | Raw socket sniffing via `network_monitor.py`. Flags excessive TCP packets possessing the SYN flag without ACK. | **Volumetric Alert Raised** |
| **UDP Flood** | Network (L4) | Packet velocity tracking on high-velocity UDP traffic bursts (`> 500 pkts / 5s`). | **Volumetric Alert Raised** |
| **ICMP Ping Flood** | Network (L3) | Threshold tracking on volumetric ICMP Echo Request bursts. | **Volumetric Alert Raised** |

---

## 🚀 Quick Start Guide

### 1. Prerequisites
- Python 3.10+
- Git
- *(Optional)* MongoDB running on `localhost:27017` (if not detected, local JSON storage is used automatically).
- *(Optional)* [Npcap](https://npcap.com/) on Windows if running the raw packet sniffer (`network_monitor.py`).

### 2. Installation
```bash
# Clone the repository

# Create virtual environment
python -m venv venv

# Activate virtual environment:
# On Windows:
venv\Scripts\activate
# On Linux / macOS:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 3. Running Core Services

#### Terminal 1 — Start Central IDS Engine & API (Port 5000)
```bash
python ids_engine.py
```
*Output confirms database mode (MongoDB or JSON) and loads baseline detection rules.*

#### Terminal 2 — Start mitmproxy In-Line WAF (Port 8080)
```bash
mitmdump --mode reverse:http://localhost:81 -s proxy_interceptor.py --listen-port 8080
```
*Listens on port `8080`, actively inspecting all inbound traffic and forwarding clean requests to backend port `81`.*

#### Terminal 3 (Optional) — Start Raw Packet Network Sniffer
```bash
# On Linux (requires sudo) / Windows (requires Administrator terminal):
python network_monitor.py
```

Open your browser to access the security dashboard:  
👉 **[http://localhost:5000](http://localhost:5000)**

---

## 🧪 Demonstration & Attack Verification Suite

A self-contained testing environment is provided in the [`demo/`](demo/) directory to verify detection efficacy without needing a live legacy audit server.

### Step 1: Start the Vulnerable Target Application
In a new terminal:
```bash
python demo/vulnerable_portal.py
```
*Simulates LedgerWall's legacy audit login portal on `http://localhost:81`.*

### Step 2: Test In-Line Active Blocking via Browser
Open your browser and navigate through the protected proxy:  
👉 **`http://localhost:8080/login.php`**

Try entering a classic SQL injection into the auditor username field:
```sql
admin' OR 1=1--
```
**Immediate Result:**
1. **In Browser:** An **HTTP 403 Forbidden** security block page appears, displaying the threat classification (`SQL Injection (SQLi)`), client IP, and incident ID.
2. **Backend Server:** Port `81` receives nothing—the database is completely protected.
3. **In `mitmdump` Console:**
   ```text
   [MITM] [ACTION: BLOCKED] SQL Injection (SQLi) from 127.0.0.1 -> http://localhost:8080/login.php (HTTP 403)
   ```
4. **On Web Dashboard (`:5000`):** The threat radar widget pulses red, the Blocked Attacks counter increments, and an entry tagged `BLOCKED` appears in the live audit feed.

### Step 3: Run the Automated 20-Payload Verification Test
In another terminal:
```bash
python demo/simulate_attacks.py --all
```
This script replicates the exact evaluation methodology from Chapter 4 of the dissertation:
- Dispatches the 20 attack vectors (SQLi, XSS, Path Traversal, DOM edge cases).
- Dispatches a 35-request volumetric burst within 2 seconds to test the application DDoS threshold trigger.

---

## 📡 REST API Reference

The IDS Engine exposes a full programmatic REST API on port `5000`:

| Endpoint | Method | Description |
|---|---|---|
| `/api/alerts` | `GET` | Paginated incident logs with query parameters (`category`, `severity`, `ip`, `page`, `limit`). |
| `/api/stats` | `GET` | Aggregated analytics (hourly breakdown, attack categories, top offending IPs). |
| `/api/system` | `GET` | Real-time host telemetry (RAM usage in MB via psutil, CPU %, active rule count, uptime). |
| `/api/get-rules` | `GET` | Retrieves all active detection rules. |
| `/api/add-rule` | `POST` | Registers a new custom JSON inspection rule. |
| `/api/update-rule` | `POST` | Updates an existing inspection rule by ID. |
| `/api/delete-rule` | `POST` | Deletes an inspection rule. |
| `/api/reset-logs` | `POST` | Flushes all incident audit logs and resets tracking counters. |
| `/api/blocklist` | `GET` | Returns list of currently blocked source IP addresses. |
| `/api/blocklist/add` | `POST` | Manually adds an IP address to the blocklist. |
| `/api/blocklist/remove`| `POST` | Removes an IP from the blocklist. |
| `/api/config` | `GET / POST`| Reads or updates real-time rate-limiting thresholds and cooldown windows. |

---

## ⚖️ License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details. Open-source and free for educational and commercial use.
