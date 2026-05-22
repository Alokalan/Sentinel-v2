from collections import defaultdict, Counter
from datetime import datetime, timedelta
import json
import os

DATA_FILE = os.path.join(os.path.dirname(__file__), '..', 'data', 'sessions.json')
ALERT_FILE = os.path.join(os.path.dirname(__file__), '..', 'data', 'alerts.json')

PORT_SCAN_THRESHOLD = 15
FLOOD_THRESHOLD = 100
TIME_WINDOW = 10


def load_packets():
    if not os.path.exists(DATA_FILE):
        return []
    try:
        with open(DATA_FILE) as f:
            return json.load(f)
    except (json.JSONDecodeError, ValueError):
        return []


def save_alerts(alerts):
    os.makedirs(os.path.dirname(ALERT_FILE), exist_ok=True)
    existing = []
    if os.path.exists(ALERT_FILE):
        with open(ALERT_FILE) as f:
            existing = json.load(f)
    existing.extend(alerts)
    with open(ALERT_FILE, 'w') as f:
        json.dump(existing, f)


def protocol_stats(packets):
    counts = Counter(p["protocol"] for p in packets)
    return dict(counts)


def top_ips(packets, n=10):
    src_counts = Counter(p["src"] for p in packets)
    return src_counts.most_common(n)


def top_ports(packets, n=10):
    ports = [p["dport"] for p in packets if p["dport"]]
    return Counter(ports).most_common(n)


def dns_queries(packets):
    return [p["dns_query"] for p in packets if p.get("dns_query")]


def traffic_over_time(packets):
    buckets = defaultdict(int)
    for p in packets:
        ts = p["timestamp"][:16]
        buckets[ts] += 1
    return dict(sorted(buckets.items()))


def detect_port_scans(packets):
    src_ports = defaultdict(set)
    for p in packets:
        if p["protocol"] == "TCP" and p.get("dport"):
            src_ports[p["src"]].add(p["dport"])

    alerts = []
    for src, ports in src_ports.items():
        if len(ports) >= PORT_SCAN_THRESHOLD:
            alerts.append({
                "type": "PORT_SCAN",
                "src": src,
                "ports_hit": len(ports),
                "timestamp": datetime.now().isoformat(),
                "severity": "HIGH"
            })
    return alerts


def detect_floods(packets):
    now = datetime.now()
    window_start = (now - timedelta(seconds=TIME_WINDOW)).isoformat()
    recent = [p for p in packets if p["timestamp"] >= window_start]

    src_counts = Counter(p["src"] for p in recent)
    alerts = []
    for src, count in src_counts.items():
        if count >= FLOOD_THRESHOLD:
            alerts.append({
                "type": "TRAFFIC_FLOOD",
                "src": src,
                "packet_count": count,
                "window_seconds": TIME_WINDOW,
                "timestamp": now.isoformat(),
                "severity": "CRITICAL"
            })
    return alerts


def detect_suspicious_dns(packets):
    queries = dns_queries(packets)
    long_domains = [q for q in queries if len(q) > 50]
    alerts = []
    for domain in long_domains:
        alerts.append({
            "type": "SUSPICIOUS_DNS",
            "domain": domain,
            "reason": "Unusually long domain (possible DNS tunneling)",
            "timestamp": datetime.now().isoformat(),
            "severity": "MEDIUM"
        })
    return alerts


def run_all_detections(packets):
    alerts = []
    alerts.extend(detect_port_scans(packets))
    alerts.extend(detect_floods(packets))
    alerts.extend(detect_suspicious_dns(packets))
    if alerts:
        save_alerts(alerts)
    return alerts


def full_report(packets):
    return {
        "total_packets": len(packets),
        "protocol_stats": protocol_stats(packets),
        "top_src_ips": top_ips(packets),
        "top_dst_ports": top_ports(packets),
        "dns_queries": dns_queries(packets)[:20],
        "traffic_over_time": traffic_over_time(packets),
        "alerts": run_all_detections(packets),
    }