"""
LedgerWall IDS — Network Layer Monitor (Scapy)
===============================================
Monitors raw network packets at the OS level and reports high packet-rate
events (potential DDoS / flood attacks) to the IDS engine via SocketIO.

This provides the NETWORK LAYER component of the IDS, complementing the
APPLICATION LAYER interception done by mitmproxy.

Detects:
  - SYN flood (TCP with SYN flag only)
  - UDP flood
  - ICMP flood (ping flood)

Requirements:
  - Run with administrator / root privileges (raw socket access)
  - scapy installed: pip install scapy
  - python-socketio[client] installed

Usage:
    python scapy_monitor.py [--interface IFACE] [--ids-url URL]
    Example: python scapy_monitor.py --interface eth0 --ids-url http://localhost:5000

NOTE: On Windows, Npcap must be installed for Scapy raw packet capture.
      Download from: https://npcap.com/
"""

import argparse
import time
import threading
from collections import defaultdict

try:
    import socketio as sio_module
except ImportError:
    print("[ScapyMon] ERROR: python-socketio not installed. Run: pip install python-socketio")
    exit(1)

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP
except ImportError:
    print("[ScapyMon] ERROR: scapy not installed. Run: pip install scapy")
    exit(1)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
REPORT_INTERVAL = 2      # seconds between stat reports to IDS engine
MIN_PPS_THRESHOLD = 50   # minimum pkt/s to even report (reduce noise)

# Per-protocol packet counters: {ip: [timestamps]}
_pkt_tracker: dict[str, dict[str, list]] = defaultdict(lambda: defaultdict(list))
_lock = threading.Lock()

# SocketIO client
sio = sio_module.Client(reconnection=True, reconnection_delay=3)
_connected = False


@sio.event
def connect():
    global _connected
    _connected = True
    print("[ScapyMon] Connected to IDS engine")


@sio.event
def disconnect():
    global _connected
    _connected = False
    print("[ScapyMon] Disconnected from IDS engine")


def _ensure_connected(ids_url: str):
    global _connected
    if not _connected:
        try:
            sio.connect(ids_url, namespaces=["/"])
        except Exception as e:
            print(f"[ScapyMon] Cannot connect to IDS: {e}")


# ---------------------------------------------------------------------------
# Packet handler
# ---------------------------------------------------------------------------

def _handle_packet(pkt):
    if not pkt.haslayer(IP):
        return

    src_ip = pkt[IP].src
    now = time.time()

    with _lock:
        if pkt.haslayer(TCP):
            flags = pkt[TCP].flags
            # SYN flag only (SYN=0x02, no ACK=0x10)
            if flags & 0x02 and not (flags & 0x10):
                _pkt_tracker[src_ip]["SYN"].append(now)
        elif pkt.haslayer(UDP):
            _pkt_tracker[src_ip]["UDP"].append(now)
        elif pkt.haslayer(ICMP):
            _pkt_tracker[src_ip]["ICMP"].append(now)


# ---------------------------------------------------------------------------
# Reporter thread — periodically flushes stats to IDS engine
# ---------------------------------------------------------------------------

def _reporter_thread(ids_url: str):
    while True:
        time.sleep(REPORT_INTERVAL)
        _ensure_connected(ids_url)
        if not _connected:
            continue

        now = time.time()
        with _lock:
            # Clean up old entries and compute pps
            to_report = []
            for ip, protos in list(_pkt_tracker.items()):
                for proto, timestamps in list(protos.items()):
                    # Keep only last 10 seconds
                    protos[proto] = [t for t in timestamps if now - t <= 10]
                    pps = len(protos[proto]) / 10.0
                    if pps >= MIN_PPS_THRESHOLD:
                        to_report.append({
                            "src_ip": ip,
                            "proto": proto,
                            "pps": round(pps, 1),
                            "count_10s": len(protos[proto]),
                        })

                # Remove IPs with no recent packets
                _pkt_tracker[ip] = {
                    k: v for k, v in protos.items() if v
                }
                if not _pkt_tracker[ip]:
                    del _pkt_tracker[ip]

        for event_data in to_report:
            try:
                sio.emit("packet_event", event_data, namespace="/")
            except Exception as e:
                print(f"[ScapyMon] Emit error: {e}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="LedgerWall IDS — Network Layer Monitor")
    parser.add_argument(
        "--interface", "-i",
        default=None,
        help="Network interface to sniff on (default: auto-detect). E.g. eth0, Wi-Fi"
    )
    parser.add_argument(
        "--ids-url",
        default="http://localhost:5000",
        help="URL of the IDS engine (default: http://localhost:5000)"
    )
    parser.add_argument(
        "--filter",
        default="ip",
        help="BPF filter string (default: 'ip')"
    )
    args = parser.parse_args()

    print(f"[ScapyMon] LedgerWall Network Layer Monitor starting...")
    print(f"[ScapyMon] IDS Engine: {args.ids_url}")
    print(f"[ScapyMon] Interface: {args.interface or 'auto'}")
    print(f"[ScapyMon] BPF Filter: {args.filter}")

    # Initial connection attempt
    _ensure_connected(args.ids_url)

    # Start reporter thread
    reporter = threading.Thread(target=_reporter_thread, args=(args.ids_url,), daemon=True)
    reporter.start()

    print("[ScapyMon] Sniffing packets... (Ctrl+C to stop)")
    try:
        sniff(
            iface=args.interface,
            filter=args.filter,
            prn=_handle_packet,
            store=False,  # Don't store packets in memory (lightweight)
        )
    except KeyboardInterrupt:
        print("\n[ScapyMon] Stopped by user")
    finally:
        if _connected:
            sio.disconnect()


if __name__ == "__main__":
    main()
