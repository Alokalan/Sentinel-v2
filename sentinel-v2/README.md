# 🛡️ Sentinel v2 — Network Traffic Analyzer

A Python-based network traffic analyzer with real-time packet capture, threat detection, GeoIP lookup, and an interactive web dashboard.

## Features
- **Live packet capture** via Scapy (TCP, UDP, ICMP, DNS)
- **Threat detection** — port scan detection, traffic flood alerts, suspicious DNS
- **GeoIP lookup** — maps source IPs to countries/cities
- **Streamlit dashboard** — live charts, protocol breakdown, alert panel
- **Export** — CSV and JSON export from dashboard

## Setup

```bash
pip install -r requirements.txt
```

> Requires root/admin privileges for packet capture.

## Usage

```bash
# Capture packets (default interface)
sudo python main.py capture

# Capture on specific interface, limit to 500 packets
sudo python main.py capture eth0 500

# Print report in terminal
python main.py report

# Launch web dashboard
python main.py dashboard

# Clear all data
python main.py clear
```

## Project Structure

```
sentinel-v2/
├── core/
│   ├── capture.py       # Scapy packet sniffer
│   ├── analyzer.py      # Stats + threat detection
│   └── geoip.py         # IP geolocation (ip-api.com)
├── dashboard/
│   └── app.py           # Streamlit dashboard
├── data/                # Auto-created at runtime
│   ├── sessions.json    # Captured packets
│   └── alerts.json      # Detected threats
├── main.py              # CLI entry point
└── requirements.txt
```

## Detection Logic

| Threat | Trigger |
|---|---|
| Port Scan | Single IP hits 15+ distinct ports |
| Traffic Flood | 100+ packets from one IP in 10s |
| Suspicious DNS | Domain name longer than 50 chars |
