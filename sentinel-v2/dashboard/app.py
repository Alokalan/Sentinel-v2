import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import json
import os
import sys
import time

sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
from core.analyzer import full_report, load_packets
from core.geoip import bulk_lookup

DATA_FILE = os.path.join(os.path.dirname(__file__), '..', 'data', 'sessions.json')
ALERT_FILE = os.path.join(os.path.dirname(__file__), '..', 'data', 'alerts.json')

st.set_page_config(
    page_title="Sentinel v2",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Inter:wght@300;400;600&display=swap');

    html, body, [class*="css"] { font-family: 'Inter', sans-serif; }
    .stApp { background-color: #0d1117; color: #e6edf3; }

    .metric-card {
        background: #161b22;
        border: 1px solid #30363d;
        border-radius: 8px;
        padding: 1.2rem;
        text-align: center;
    }
    .metric-value {
        font-family: 'JetBrains Mono', monospace;
        font-size: 2rem;
        font-weight: 700;
        color: #58a6ff;
    }
    .metric-label {
        font-size: 0.75rem;
        color: #8b949e;
        text-transform: uppercase;
        letter-spacing: 0.1em;
        margin-top: 0.3rem;
    }
    .alert-critical {
        background: #3d1f1f; border-left: 4px solid #f85149;
        padding: 0.8rem 1rem; border-radius: 4px; margin: 0.5rem 0;
        font-family: 'JetBrains Mono', monospace; font-size: 0.8rem;
    }
    .alert-high {
        background: #2d2210; border-left: 4px solid #d29922;
        padding: 0.8rem 1rem; border-radius: 4px; margin: 0.5rem 0;
        font-family: 'JetBrains Mono', monospace; font-size: 0.8rem;
    }
    .alert-medium {
        background: #1b2a3b; border-left: 4px solid #388bfd;
        padding: 0.8rem 1rem; border-radius: 4px; margin: 0.5rem 0;
        font-family: 'JetBrains Mono', monospace; font-size: 0.8rem;
    }
    .sentinel-title {
        font-family: 'JetBrains Mono', monospace;
        font-size: 1.8rem; font-weight: 700;
        color: #58a6ff; letter-spacing: 0.05em;
    }
    [data-testid="stSidebar"] { background-color: #161b22; border-right: 1px solid #30363d; }
</style>
""", unsafe_allow_html=True)


def load_alerts():
    if not os.path.exists(ALERT_FILE):
        return []
    with open(ALERT_FILE) as f:
        return json.load(f)


def render_alert(alert):
    sev = alert.get("severity", "MEDIUM")
    cls = {"CRITICAL": "alert-critical", "HIGH": "alert-high"}.get(sev, "alert-medium")
    atype = alert.get("type", "UNKNOWN")
    detail = ""
    if atype == "PORT_SCAN":
        detail = f"{alert['src']} hit {alert['ports_hit']} ports"
    elif atype == "TRAFFIC_FLOOD":
        detail = f"{alert['src']} sent {alert['packet_count']} pkts in {alert['window_seconds']}s"
    elif atype == "SUSPICIOUS_DNS":
        detail = f"{alert['domain'][:60]}..."
    st.markdown(f'<div class="{cls}"><b>[{sev}] {atype}</b> — {detail}</div>', unsafe_allow_html=True)


st.sidebar.markdown('<div class="sentinel-title">🛡️ SENTINEL</div>', unsafe_allow_html=True)
st.sidebar.markdown('<p style="color:#8b949e;font-size:0.75rem;margin-top:-0.5rem;">Network Traffic Analyzer v2</p>', unsafe_allow_html=True)
st.sidebar.divider()

auto_refresh = st.sidebar.toggle("Auto-refresh (5s)", value=False)
show_geo = st.sidebar.toggle("GeoIP Lookup", value=False)
st.sidebar.divider()
st.sidebar.markdown('<p style="color:#8b949e;font-size:0.7rem;">Data file:<br><code style="color:#58a6ff">data/sessions.json</code></p>', unsafe_allow_html=True)

if not os.path.exists(DATA_FILE):
    st.markdown('<div class="sentinel-title">🛡️ SENTINEL v2</div>', unsafe_allow_html=True)
    st.warning("No capture data found. Run `python main.py capture` to start sniffing.")
    st.stop()

packets = load_packets()
report = full_report(packets)
alerts = load_alerts()

st.markdown('<div class="sentinel-title">🛡️ SENTINEL v2</div>', unsafe_allow_html=True)
st.markdown(f'<p style="color:#8b949e;font-size:0.8rem;">Last updated: {pd.Timestamp.now().strftime("%H:%M:%S")} · {len(packets)} packets captured</p>', unsafe_allow_html=True)

col1, col2, col3, col4 = st.columns(4)
stats = [
    (report["total_packets"], "Total Packets"),
    (len(set(p["src"] for p in packets)), "Unique IPs"),
    (len(report["dns_queries"]), "DNS Queries"),
    (len(alerts), "Alerts"),
]
for col, (val, label) in zip([col1, col2, col3, col4], stats):
    with col:
        st.markdown(f'<div class="metric-card"><div class="metric-value">{val}</div><div class="metric-label">{label}</div></div>', unsafe_allow_html=True)

st.divider()

col_left, col_right = st.columns([3, 2])

with col_left:
    st.subheader("Traffic Over Time")
    tot = report["traffic_over_time"]
    if tot:
        df_time = pd.DataFrame(list(tot.items()), columns=["Time", "Packets"])
        fig = px.area(df_time, x="Time", y="Packets",
                      color_discrete_sequence=["#58a6ff"],
                      template="plotly_dark")
        fig.update_layout(
            paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
            margin=dict(l=0, r=0, t=10, b=0), height=220,
            xaxis=dict(gridcolor="#21262d"), yaxis=dict(gridcolor="#21262d")
        )
        st.plotly_chart(fig, use_container_width=True)

with col_right:
    st.subheader("Protocol Distribution")
    proto = report["protocol_stats"]
    if proto:
        fig2 = px.pie(values=list(proto.values()), names=list(proto.keys()),
                      color_discrete_sequence=["#58a6ff", "#3fb950", "#d29922", "#f85149", "#8b949e"],
                      template="plotly_dark", hole=0.5)
        fig2.update_layout(
            paper_bgcolor="rgba(0,0,0,0)", margin=dict(l=0, r=0, t=10, b=0), height=220,
            legend=dict(font=dict(size=11))
        )
        st.plotly_chart(fig2, use_container_width=True)

col_a, col_b = st.columns(2)

with col_a:
    st.subheader("Top Source IPs")
    top_ips_data = report["top_src_ips"]
    if top_ips_data:
        df_ips = pd.DataFrame(top_ips_data, columns=["IP", "Packets"])
        fig3 = px.bar(df_ips, x="Packets", y="IP", orientation="h",
                      color_discrete_sequence=["#388bfd"], template="plotly_dark")
        fig3.update_layout(
            paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
            margin=dict(l=0, r=0, t=10, b=0), height=250,
            yaxis=dict(gridcolor="#21262d", autorange="reversed"),
            xaxis=dict(gridcolor="#21262d")
        )
        st.plotly_chart(fig3, use_container_width=True)

with col_b:
    st.subheader("Top Destination Ports")
    top_ports_data = report["top_dst_ports"]
    if top_ports_data:
        df_ports = pd.DataFrame(top_ports_data, columns=["Port", "Count"])
        df_ports["Port"] = df_ports["Port"].astype(str)
        fig4 = px.bar(df_ports, x="Count", y="Port", orientation="h",
                      color_discrete_sequence=["#3fb950"], template="plotly_dark")
        fig4.update_layout(
            paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
            margin=dict(l=0, r=0, t=10, b=0), height=250,
            yaxis=dict(gridcolor="#21262d", autorange="reversed"),
            xaxis=dict(gridcolor="#21262d")
        )
        st.plotly_chart(fig4, use_container_width=True)

st.divider()
st.subheader("🚨 Alerts")
if not alerts:
    st.markdown('<p style="color:#3fb950;font-size:0.9rem;">✓ No threats detected</p>', unsafe_allow_html=True)
else:
    for alert in sorted(alerts, key=lambda x: x.get("severity", ""), reverse=True)[:20]:
        render_alert(alert)

if report["dns_queries"]:
    st.divider()
    st.subheader("DNS Queries")
    dns_df = pd.DataFrame(report["dns_queries"], columns=["Domain"])
    st.dataframe(dns_df, use_container_width=True, height=200)

if show_geo:
    st.divider()
    st.subheader("🌍 GeoIP Map")
    unique_ips = list(set(p["src"] for p in packets))[:30]
    with st.spinner("Looking up IPs..."):
        geo_data = bulk_lookup(unique_ips)
    map_rows = [{"IP": ip, **info} for ip, info in geo_data.items() if info["lat"] != 0]
    if map_rows:
        df_map = pd.DataFrame(map_rows)
        fig_map = px.scatter_geo(df_map, lat="lat", lon="lon", hover_name="IP",
                                  hover_data=["country", "city", "isp"],
                                  color_discrete_sequence=["#58a6ff"],
                                  template="plotly_dark")
        fig_map.update_layout(
            paper_bgcolor="#0d1117", geo=dict(bgcolor="#161b22", lakecolor="#0d1117",
            landcolor="#21262d", showland=True, showlakes=True),
            margin=dict(l=0, r=0, t=0, b=0), height=400
        )
        st.plotly_chart(fig_map, use_container_width=True)

st.divider()
st.subheader("Raw Packet Log")
df_raw = pd.DataFrame(packets).tail(100)
st.dataframe(df_raw, use_container_width=True, height=250)

col_exp1, col_exp2 = st.columns(2)
with col_exp1:
    csv = df_raw.to_csv(index=False)
    st.download_button("⬇ Export CSV", csv, "sentinel_packets.csv", "text/csv")
with col_exp2:
    st.download_button("⬇ Export JSON", json.dumps(packets[-100:], indent=2),
                       "sentinel_packets.json", "application/json")

if auto_refresh:
    time.sleep(5)
    st.rerun()
