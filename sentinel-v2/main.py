import sys
import os
import json
import subprocess

sys.path.append(os.path.dirname(__file__))
from core.analyzer import full_report, load_packets

BANNER = """
 ███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗     
 ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║     
 ███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║     
 ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║     
 ███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗
 ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝
                        Network Traffic Analyzer v2
"""

def cmd_capture(args):
    from core.capture import start
    iface = args[0] if args else None
    count = int(args[1]) if len(args) > 1 else 0
    start(interface=iface, packet_count=count)

def cmd_report(args):
    packets = load_packets()
    if not packets:
        print("[!] No data found. Run: python main.py capture")
        return
    report = full_report(packets)
    print(f"\n{'='*50}")
    print(f"  Total Packets : {report['total_packets']}")
    print(f"  Protocols     : {report['protocol_stats']}")
    print(f"\n  Top Source IPs:")
    for ip, count in report["top_src_ips"][:5]:
        print(f"    {ip:<20} {count} packets")
    print(f"\n  Top Ports:")
    for port, count in report["top_dst_ports"][:5]:
        print(f"    Port {port:<10} {count} hits")
    print(f"\n  Alerts ({len(report['alerts'])}):")
    for alert in report["alerts"]:
        print(f"    [{alert['severity']}] {alert['type']} — {alert.get('src', alert.get('domain', ''))}")
    print(f"{'='*50}\n")

def cmd_dashboard(args):
    dashboard_path = os.path.join(os.path.dirname(__file__), 'dashboard', 'app.py')
    print("[Sentinel v2] Launching dashboard...")
    subprocess.run(["streamlit", "run", dashboard_path])

def cmd_clear(args):
    for fname in ["sessions.json", "alerts.json"]:
        path = os.path.join(os.path.dirname(__file__), "data", fname)
        if os.path.exists(path):
            os.remove(path)
    print("[Sentinel v2] Data cleared.")

COMMANDS = {
    "capture": (cmd_capture, "Start capturing packets  [iface] [count]"),
    "report":  (cmd_report,  "Print analysis report in terminal"),
    "dashboard": (cmd_dashboard, "Launch Streamlit dashboard"),
    "clear":   (cmd_clear,   "Clear all captured data"),
}

def main():
    print(BANNER)
    if len(sys.argv) < 2 or sys.argv[1] not in COMMANDS:
        print("Usage: python main.py <command> [args]\n")
        print("Commands:")
        for cmd, (_, desc) in COMMANDS.items():
            print(f"  {cmd:<12} {desc}")
        print()
        return
    cmd = sys.argv[1]
    args = sys.argv[2:]
    COMMANDS[cmd][0](args)

if __name__ == "__main__":
    main()
