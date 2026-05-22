from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS, DNSQR
from datetime import datetime
import threading
import json
import os

DATA_FILE = os.path.join(os.path.dirname(__file__), '..', 'data', 'sessions.json')

_lock = threading.Lock()
_packets = []


def _load():
    if not os.path.exists(DATA_FILE):
        return []
    try:
        with open(DATA_FILE) as f:
            return json.load(f)
    except (json.JSONDecodeError, ValueError):
        return []


def _save(data):
    os.makedirs(os.path.dirname(DATA_FILE), exist_ok=True)
    tmp = DATA_FILE + ".tmp"
    with open(tmp, 'w') as f:
        json.dump(data, f)
    os.replace(tmp, DATA_FILE)


def _process(pkt):
    if not pkt.haslayer(IP):
        return

    record = {
        "timestamp": datetime.now().isoformat(),
        "src": pkt[IP].src,
        "dst": pkt[IP].dst,
        "size": len(pkt),
        "protocol": "OTHER",
        "sport": None,
        "dport": None,
        "flags": None,
        "dns_query": None,
    }

    if pkt.haslayer(TCP):
        record["protocol"] = "TCP"
        record["sport"] = pkt[TCP].sport
        record["dport"] = pkt[TCP].dport
        record["flags"] = str(pkt[TCP].flags)
    elif pkt.haslayer(UDP):
        record["protocol"] = "UDP"
        record["sport"] = pkt[UDP].sport
        record["dport"] = pkt[UDP].dport
    elif pkt.haslayer(ICMP):
        record["protocol"] = "ICMP"

    if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
        record["dns_query"] = pkt[DNSQR].qname.decode(errors="ignore").rstrip(".")
        record["protocol"] = "DNS"

    with _lock:
        _packets.append(record)
        if len(_packets) % 10 == 0:
            existing = _load()
            existing.extend(_packets[-10:])
            _save(existing)


def start(interface=None, packet_count=0):
    print(f"[Sentinel v2] Sniffing on {'default' if not interface else interface}...")
    sniff(iface=interface, prn=_process, count=packet_count, store=False)