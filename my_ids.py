from scapy.all import sniff, IP, TCP, UDP, ICMP
import time
import logging
import socket
from collections import defaultdict

LOG_FILE = "ids_alerts.log"
ALERT_COOLDOWN = 3
SCAN_THRESHOLD = 15
BRUTE_THRESHOLD = 5

WHITELIST = {
    "127.0.0.1",
    "::1",
}

SIGNATURES = [
    # Port Scanning
    (
        "SYN Port Scan",
        lambda pkt: (
            pkt.haslayer(TCP) and pkt[TCP].flags == "S" and not pkt[TCP].flags & 0x10
        ),
    ),
    # SSH Brute Force
    ("SSH Brute Force Attempt", lambda pkt: pkt.haslayer(TCP) and pkt[TCP].dport == 22),
    # DNS Queries
    ("Suspicious DNS Lookup", lambda pkt: pkt.haslayer(UDP) and pkt[UDP].dport == 53),
    # ICMP Flood / Ping Sweep
    ("ICMP Ping Detected", lambda pkt: pkt.haslayer(ICMP) and pkt[ICMP].type == 8),
    # Known Malicious Subnet
    (
        "Traffic from Known Suspicious Range",
        lambda pkt: pkt.haslayer(IP) and pkt[IP].src.startswith("198.51.100"),
    ),
    # SQL Injection Pattern
    (
        "Possible SQL Injection Attempt",
        lambda pkt: (
            pkt.haslayer(TCP)
            and pkt[TCP].dport in [80, 443]
            and hasattr(pkt, "load")
            and b"SELECT" in bytes(pkt.payload).upper()
        ),
    ),
]

alert_tracker = {}
connection_tracker = defaultdict(
    lambda: {"ports": set(), "ssh_attempts": 0, "last_reset": time.time()}
)

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

console = logging.StreamHandler()
console.setFormatter(logging.Formatter("%(message)s"))
logging.getLogger().addHandler(console)


def is_whitelisted(ip):
    """Skip trusted IPs entirely"""
    return ip in WHITELIST


def should_alert(alert_id):
    """Prevent spam — cooldown between alerts"""
    now = time.time()
    if alert_id not in alert_tracker or now - alert_tracker[alert_id] > ALERT_COOLDOWN:
        alert_tracker[alert_id] = now
        return True
    return False


def analyze_behavior(src_ip, dst_ip, pkt):
    """Behavioral analysis — detect patterns not just single packets"""
    now = time.time()
    conn = connection_tracker[src_ip]

    if now - conn["last_reset"] > 60:
        conn["ports"].clear()
        conn["ssh_attempts"] = 0
        conn["last_reset"] = now

    if pkt.haslayer(TCP):
        conn["ports"].add(pkt[TCP].dport)
        if pkt[TCP].dport == 22:
            conn["ssh_attempts"] += 1

    if len(conn["ports"]) > SCAN_THRESHOLD and should_alert(f"SCAN:{src_ip}"):
        logging.warning(
            f"⚠️  HIGH PORT SCAN — {src_ip} probed {len(conn['ports'])}+ ports → {dst_ip}"
        )

    if conn["ssh_attempts"] > BRUTE_THRESHOLD and should_alert(f"BRUTE:{src_ip}"):
        logging.critical(
            f"🚨 SSH BRUTE FORCE — {src_ip} made {conn['ssh_attempts']} attempts → {dst_ip}"
        )


def packet_handler(pkt):
    if not pkt.haslayer(IP):
        return

    src = pkt[IP].src
    dst = pkt[IP].dst

    if is_whitelisted(src) or is_whitelisted(dst):
        return

    for name, check in SIGNATURES:
        try:
            if check(pkt) and should_alert(f"{name}:{src}"):
                logging.warning(f"⚠️  {name} — {src} → {dst}")
        except Exception:
            pass

    analyze_behavior(src, dst, pkt)


def start_ids(iface="eth0"):
    print("=" * 60)
    print("🛡️  ENHANCED INTRUSION DETECTION SYSTEM — ACTIVE")
    print(f"📡 Interface: {iface}")
    print(f"📋 Rules: {len(SIGNATURES)} signature + behavioral analysis")
    print(f"🚫 Whitelisted: {len(WHITELIST)} trusted addresses")
    print(f"📝 Logging to: {LOG_FILE}")
    print("=" * 60)
    print("Press Ctrl+C to stop\n")

    try:
        sniff(iface=iface, prn=packet_handler, store=0)
    except PermissionError:
        print("\n❌ ERROR: Need root privileges! Run with: sudo python3 my_ids.py")
    except KeyboardInterrupt:
        print("\n🛑 IDS stopped. Logs saved to:", LOG_FILE)


if __name__ == "__main__":
    start_ids(iface="eth0")

