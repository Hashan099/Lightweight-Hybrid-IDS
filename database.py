"""
LedgerWall IDS — Database Abstraction Layer
============================================
Provides unified storage operations for alerts, rules, and telemetry.
Automatically selects the storage backend at startup:

  1. MongoDB  — if reachable on IDS_MONGO_URI (default: mongodb://localhost:27017/idsdb)
  2. JSON File — zero-dependency local storage (stored in ./data/)

Automatically self-initializes with 33+ baseline security rules on first run
if no existing rules are found.
"""

import json
import os
import threading
import time
import uuid
from copy import deepcopy
from datetime import datetime
from pathlib import Path

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
MONGO_URI = os.environ.get("IDS_MONGO_URI", "mongodb://localhost:27017/idsdb")
MONGO_TIMEOUT_MS = 1500

DATA_DIR = Path(__file__).parent / "data"

# ---------------------------------------------------------------------------
# Baseline Security Rules (Auto-seeded if storage is empty)
# ---------------------------------------------------------------------------
DEFAULT_BASELINE_RULES = [
    # SQLi
    {"category": "SQLi", "severity": "HIGH", "url": "union select", "alert": "[SQLi] UNION SELECT injection attempt detected"},
    {"category": "SQLi", "severity": "HIGH", "url": "' or '1'='1", "alert": "[SQLi] Classic OR-based SQL injection detected"},
    {"category": "SQLi", "severity": "HIGH", "url": "drop table", "alert": "[SQLi] DROP TABLE command in URL — destructive SQLi attempt"},
    {"category": "SQLi", "severity": "HIGH", "content": "union select", "alert": "[SQLi] UNION SELECT in POST body — SQL injection attempt"},
    {"category": "SQLi", "severity": "HIGH", "content": "'; drop table", "alert": "[SQLi] DROP TABLE in POST body — destructive SQL injection"},
    {"category": "SQLi", "severity": "MEDIUM", "url": "sleep(", "alert": "[SQLi] Time-based blind SQLi — SLEEP() detected in URL"},
    {"category": "SQLi", "severity": "MEDIUM", "url": "benchmark(", "alert": "[SQLi] Time-based blind SQLi — BENCHMARK() detected"},
    {"category": "SQLi", "severity": "HIGH", "url": "information_schema", "alert": "[SQLi] INFORMATION_SCHEMA enumeration attempt"},
    {"category": "SQLi", "severity": "CRITICAL", "url": "into outfile", "alert": "[SQLi] INTO OUTFILE detected — file write attempt via SQLi"},

    # XSS
    {"category": "XSS", "severity": "MEDIUM", "url": "<script>", "alert": "[XSS] Script tag detected in URL"},
    {"category": "XSS", "severity": "MEDIUM", "content": "<script>", "alert": "[XSS] Script tag detected in POST body"},
    {"category": "XSS", "severity": "MEDIUM", "url": "javascript:", "alert": "[XSS] javascript: pseudo-protocol detected"},
    {"category": "XSS", "severity": "MEDIUM", "url": "onerror=", "alert": "[XSS] onerror= event handler in URL — DOM XSS attempt"},
    {"category": "XSS", "severity": "MEDIUM", "url": "onload=", "alert": "[XSS] onload= event handler in URL — DOM XSS attempt"},
    {"category": "XSS", "severity": "LOW", "url": "alert(", "alert": "[XSS] alert() function probe detected in URL"},

    # Path Traversal
    {"category": "PathTraversal", "severity": "HIGH", "url": "../", "alert": "[PATH TRAVERSAL] Directory traversal attempt in URL"},
    {"category": "PathTraversal", "severity": "HIGH", "url": "/etc/passwd", "alert": "[PATH TRAVERSAL] Attempt to access /etc/passwd"},
    {"category": "PathTraversal", "severity": "HIGH", "url": "/etc/shadow", "alert": "[PATH TRAVERSAL] Attempt to access /etc/shadow"},
    {"category": "PathTraversal", "severity": "MEDIUM", "url": "%2e%2e%2f", "alert": "[PATH TRAVERSAL] URL-encoded traversal sequence detected"},

    # Automated Scanners
    {"category": "Scanner", "severity": "LOW", "headers": {"User-Agent": "sqlmap"}, "alert": "[SCANNER] SQLMap automated vulnerability scanner detected"},
    {"category": "Scanner", "severity": "LOW", "headers": {"User-Agent": "nikto"}, "alert": "[SCANNER] Nikto web server scanner detected"},
    {"category": "Scanner", "severity": "LOW", "headers": {"User-Agent": "nmap"}, "alert": "[SCANNER] Nmap security scanner detected"},
    {"category": "Scanner", "severity": "LOW", "headers": {"User-Agent": "masscan"}, "alert": "[SCANNER] Masscan high-speed scanner detected"},
    {"category": "Scanner", "severity": "LOW", "headers": {"User-Agent": "dirbuster"}, "alert": "[SCANNER] DirBuster brute-force scanner detected"},
    {"category": "Scanner", "severity": "LOW", "headers": {"User-Agent": "gobuster"}, "alert": "[SCANNER] GoBuster directory brute-force detected"},
    {"category": "Scanner", "severity": "LOW", "headers": {"User-Agent": "python-requests"}, "alert": "[SCANNER] Automated Python client detected"},

    # Sensitive Endpoint Probes
    {"category": "Probing", "severity": "MEDIUM", "url": "/wp-admin", "alert": "[PROBE] WordPress administrative panel probe detected"},
    {"category": "Probing", "severity": "MEDIUM", "url": "/.env", "alert": "[PROBE] Environment file access attempt — credential harvesting risk"},
    {"category": "Probing", "severity": "MEDIUM", "url": "/phpMyAdmin", "alert": "[PROBE] phpMyAdmin console probe detected"},
    {"category": "Probing", "severity": "MEDIUM", "url": "/admin/config", "alert": "[PROBE] Administrative configuration endpoint probed"},
    {"category": "Probing", "severity": "LOW", "url": "/.git", "alert": "[PROBE] Exposed .git repository directory probe detected"},
    {"category": "Probing", "severity": "HIGH", "url": "/shell", "alert": "[PROBE] Web shell backdoor access attempt detected"},
    {"category": "Probing", "severity": "HIGH", "url": "/cmd", "alert": "[PROBE] Operating system command endpoint probe detected"},
]


def _new_id() -> str:
    return uuid.uuid4().hex[:24]


# ===========================================================================
# JSON File Storage Backend
# ===========================================================================
class JsonBackend:
    def __init__(self):
        DATA_DIR.mkdir(exist_ok=True)
        self._alerts_path = DATA_DIR / "alerts.json"
        self._rules_path = DATA_DIR / "rules.json"
        self._lock = threading.RLock()
        self._ensure_files()

    def _ensure_files(self):
        with self._lock:
            if not self._alerts_path.exists():
                self._alerts_path.write_text("[]", encoding="utf-8")
            
            # Auto-seed baseline rules if rules file is absent or empty
            rules_need_seed = False
            if not self._rules_path.exists():
                rules_need_seed = True
            else:
                try:
                    data = json.loads(self._rules_path.read_text(encoding="utf-8"))
                    if not data:
                        rules_need_seed = True
                except Exception:
                    rules_need_seed = True

            if rules_need_seed:
                seeded_rules = []
                for r in DEFAULT_BASELINE_RULES:
                    doc = deepcopy(r)
                    doc["_id"] = _new_id()
                    doc["created_at"] = datetime.utcnow().isoformat()
                    seeded_rules.append(doc)
                self._write(self._rules_path, seeded_rules)

    def _read(self, path: Path) -> list:
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, FileNotFoundError):
            return []

    def _write(self, path: Path, data: list):
        tmp = path.with_suffix(".tmp")
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        tmp.replace(path)

    # Alerts Operations
    def insert_alert(self, doc: dict) -> str:
        doc = deepcopy(doc)
        doc["_id"] = _new_id()
        with self._lock:
            alerts = self._read(self._alerts_path)
            alerts.append(doc)
            self._write(self._alerts_path, alerts)
        return doc["_id"]

    def get_alerts(self, page: int = 1, limit: int = 50, category: str = None, severity: str = None, ip: str = None) -> dict:
        with self._lock:
            alerts = self._read(self._alerts_path)

        if category: alerts = [a for a in alerts if a.get("category") == category]
        if severity: alerts = [a for a in alerts if a.get("severity") == severity]
        if ip:       alerts = [a for a in alerts if a.get("ip") == ip]

        alerts.sort(key=lambda a: a.get("timestamp", 0), reverse=True)
        total = len(alerts)
        skip = (page - 1) * limit
        return {
            "alerts": alerts[skip:skip + limit],
            "total": total,
            "page": page,
            "limit": limit,
            "pages": max(1, (total + limit - 1) // limit),
        }

    def delete_all_alerts(self) -> int:
        with self._lock:
            alerts = self._read(self._alerts_path)
            count = len(alerts)
            self._write(self._alerts_path, [])
        return count

    def compute_stats(self) -> dict:
        now_ts = int(time.time())
        with self._lock:
            all_alerts = self._read(self._alerts_path)

        one_hour_ago = now_ts - 3600
        one_day_ago = now_ts - 86400

        last_hour = [a for a in all_alerts if a.get("timestamp", 0) >= one_hour_ago]
        last_day = [a for a in all_alerts if a.get("timestamp", 0) >= one_day_ago]

        by_category = {}
        by_severity = {}
        ip_counts = {}

        for a in all_alerts:
            cat = a.get("category") or "Unknown"
            sev = a.get("severity") or "MEDIUM"
            by_category[cat] = by_category.get(cat, 0) + 1
            by_severity[sev] = by_severity.get(sev, 0) + 1

        for a in last_day:
            ip = a.get("ip") or "unknown"
            ip_counts[ip] = ip_counts.get(ip, 0) + 1

        top_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:5]

        hourly = []
        import pytz
        tz = pytz.timezone("Asia/Colombo")
        for i in range(23, -1, -1):
            bucket_start = now_ts - (i + 1) * 3600
            bucket_end = now_ts - i * 3600
            count = sum(1 for a in all_alerts if bucket_start <= a.get("timestamp", 0) < bucket_end)
            label = datetime.fromtimestamp(bucket_end, tz=tz).strftime("%H:%M")
            hourly.append({"label": label, "count": count})

        return {
            "total": len(all_alerts),
            "last_hour": len(last_hour),
            "last_day": len(last_day),
            "by_category": by_category,
            "by_severity": by_severity,
            "top_ips": [{"ip": ip, "count": c} for ip, c in top_ips],
            "hourly": hourly,
            "alerts_per_min": round(len(last_hour) / 60, 2),
        }

    # Rules Operations
    def get_rules(self) -> list:
        with self._lock:
            return deepcopy(self._read(self._rules_path))

    def insert_rule(self, doc: dict) -> str:
        doc = deepcopy(doc)
        doc["_id"] = _new_id()
        doc["created_at"] = datetime.utcnow().isoformat()
        with self._lock:
            rules = self._read(self._rules_path)
            rules.append(doc)
            self._write(self._rules_path, rules)
        return doc["_id"]

    def update_rule(self, rule_id: str, updated: dict) -> bool:
        with self._lock:
            rules = self._read(self._rules_path)
            for i, rule in enumerate(rules):
                if rule.get("_id") == rule_id:
                    updated_rule = {**rule, **updated}
                    updated_rule["_id"] = rule_id
                    rules[i] = updated_rule
                    self._write(self._rules_path, rules)
                    return True
        return False

    def delete_rule(self, rule_id: str) -> bool:
        with self._lock:
            rules = self._read(self._rules_path)
            new_rules = [r for r in rules if r.get("_id") != rule_id]
            if len(new_rules) == len(rules):
                return False
            self._write(self._rules_path, new_rules)
        return True

    @property
    def backend_name(self) -> str:
        return "json"

    @property
    def backend_info(self) -> str:
        return f"JSON files @ {DATA_DIR}"


# ===========================================================================
# MongoDB Storage Backend
# ===========================================================================
class MongoBackend:
    def __init__(self, uri: str):
        from pymongo import MongoClient
        self._client = MongoClient(uri, serverSelectionTimeoutMS=MONGO_TIMEOUT_MS)
        db_name = uri.rsplit("/", 1)[-1] or "idsdb"
        self._db = self._client[db_name]
        self._alerts = self._db["alerts"]
        self._rules = self._db["rules"]
        self._uri = uri
        self._auto_seed()

    def _auto_seed(self):
        try:
            if self._rules.count_documents({}) == 0:
                seeded_rules = []
                for r in DEFAULT_BASELINE_RULES:
                    doc = deepcopy(r)
                    doc["created_at"] = datetime.utcnow().isoformat()
                    seeded_rules.append(doc)
                self._rules.insert_many(seeded_rules)
        except Exception:
            pass

    def _doc(self, d: dict) -> dict:
        d = dict(d)
        if "_id" in d:
            d["_id"] = str(d["_id"])
        return d

    def insert_alert(self, doc: dict) -> str:
        result = self._alerts.insert_one(deepcopy(doc))
        return str(result.inserted_id)

    def get_alerts(self, page: int = 1, limit: int = 50, category: str = None, severity: str = None, ip: str = None) -> dict:
        query = {}
        if category: query["category"] = category
        if severity: query["severity"] = severity
        if ip:       query["ip"] = ip

        total = self._alerts.count_documents(query)
        skip = (page - 1) * limit
        docs = list(self._alerts.find(query).sort("timestamp", -1).skip(skip).limit(limit))
        return {
            "alerts": [self._doc(d) for d in docs],
            "total": total,
            "page": page,
            "limit": limit,
            "pages": max(1, (total + limit - 1) // limit),
        }

    def delete_all_alerts(self) -> int:
        return self._alerts.delete_many({}).deleted_count

    def compute_stats(self) -> dict:
        import pytz
        tz = pytz.timezone("Asia/Colombo")
        now_ts = int(time.time())
        one_hour_ago = now_ts - 3600
        one_day_ago = now_ts - 86400

        total = self._alerts.count_documents({})
        last_hour = self._alerts.count_documents({"timestamp": {"$gte": one_hour_ago}})
        last_day = self._alerts.count_documents({"timestamp": {"$gte": one_day_ago}})

        by_category = {d["_id"]: d["count"] for d in self._alerts.aggregate([{"$group": {"_id": "$category", "count": {"$sum": 1}}}, {"$sort": {"count": -1}}]) if d["_id"]}
        by_severity = {d["_id"]: d["count"] for d in self._alerts.aggregate([{"$group": {"_id": "$severity", "count": {"$sum": 1}}}, {"$sort": {"count": -1}}]) if d["_id"]}
        top_ips = [{"ip": d["_id"], "count": d["count"]} for d in self._alerts.aggregate([{"$match": {"timestamp": {"$gte": one_day_ago}}}, {"$group": {"_id": "$ip", "count": {"$sum": 1}}}, {"$sort": {"count": -1}}, {"$limit": 5}])]

        hourly = []
        for i in range(23, -1, -1):
            bucket_start = now_ts - (i + 1) * 3600
            bucket_end = now_ts - i * 3600
            count = self._alerts.count_documents({"timestamp": {"$gte": bucket_start, "$lt": bucket_end}})
            label = datetime.fromtimestamp(bucket_end, tz=tz).strftime("%H:%M")
            hourly.append({"label": label, "count": count})

        return {
            "total": total,
            "last_hour": last_hour,
            "last_day": last_day,
            "by_category": by_category,
            "by_severity": by_severity,
            "top_ips": top_ips,
            "hourly": hourly,
            "alerts_per_min": round(last_hour / 60, 2),
        }

    def get_rules(self) -> list:
        return [self._doc(r) for r in self._rules.find({})]

    def insert_rule(self, doc: dict) -> str:
        doc = deepcopy(doc)
        doc["created_at"] = datetime.utcnow().isoformat()
        return str(self._rules.insert_one(doc).inserted_id)

    def update_rule(self, rule_id: str, updated: dict) -> bool:
        from bson import ObjectId
        try:
            return self._rules.update_one({"_id": ObjectId(rule_id)}, {"$set": updated}).modified_count > 0
        except Exception:
            return False

    def delete_rule(self, rule_id: str) -> bool:
        from bson import ObjectId
        try:
            return self._rules.delete_one({"_id": ObjectId(rule_id)}).deleted_count > 0
        except Exception:
            return False

    @property
    def backend_name(self) -> str:
        return "mongodb"

    @property
    def backend_info(self) -> str:
        return f"MongoDB @ {self._uri}"


# ===========================================================================
# Auto-Selection Factory
# ===========================================================================
def _init_storage():
    try:
        from pymongo import MongoClient
        client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=MONGO_TIMEOUT_MS)
        client.admin.command("ping")
        print(f"[DB] Connected to MongoDB ({MONGO_URI})")
        return MongoBackend(MONGO_URI)
    except Exception:
        print("[DB] MongoDB not detected. Utilizing local JSON storage in ./data/")
        return JsonBackend()


db: JsonBackend | MongoBackend = _init_storage()
