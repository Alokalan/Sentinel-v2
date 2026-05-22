# 🛡️ Sentinel v2 — Network Traffic Analyzer

A Python-based network traffic analyzer with real-time packet capture, threat detection, GeoIP lookup, and an interactive web dashboard.

## Features
- **Live packet capture** via Scapy (TCP, UDP, ICMP, DNS)
- **Threat detection** — port scan detection, traffic flood alerts, suspicious DNS query flagging
- **GeoIP lookup** — maps source IPs to countries and cities
- **Streamlit dashboard** — live charts, protocol breakdown, alert panel
- **Export** — CSV and JSON export from dashboard
- **CLI interface** — capture, report, and data management from terminal

## Requirements
- Python 3.10+
- [Npcap](https://npcap.com/#download) (Windows only) — install with **WinPcap API-compatible mode** checked

## Setup

```bash
pip install -r requirements.txt
```

## Usage

> ⚠️ **Windows:** Run CMD or PowerShell as Administrator for packet capture.

```bash
# Capture packets (default interface)
python main.py capture

# Capture on specific interface, limit to 500 packets
python main.py capture eth0 500

# Print analysis report in terminal
python main.py report

# Launch Streamlit dashboard
python main.py dashboard

# Clear all captured data
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
| Traffic Flood | 100+ packets from one IP in 10 seconds |
| Suspicious DNS | Domain name longer than 50 characters (possible DNS tunneling) |

## Tech Stack

`Python` `Scapy` `Streamlit` `Pandas` `Plotly` `Npcap`
