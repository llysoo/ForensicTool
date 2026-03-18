import os
import tempfile
import time
import pandas as pd
import streamlit as st
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from datetime import datetime
from scapy.all import rdpcap, get_if_list, sniff, wrpcap

from detectors import (
    parse_pcap_packets,
    reconstruct_sessions,
    get_traffic_summary,
    detect_port_scanning,
    detect_arp_spoofing,
    detect_ddos,
    detect_beaconing,
    detect_unusual_outbound_connections,
    detect_data_exfiltration,
    detect_icmp_flood,
    detect_large_packets,
    detect_icmp_sweep,
)

st.set_page_config(page_title="NetSleuth IR", layout="wide")

# ---------- Custom CSS ----------
st.markdown(
    """
    <style>
    .status-box {
        padding: 14px 16px;
        border-radius: 10px;
        font-weight: 600;
        margin-bottom: 10px;
        border: 1px solid transparent;
    }

    .status-clear {
        background-color: #e8f5e9;
        color: #1b5e20;
        border-color: #66bb6a;
    }

    .status-detected {
        background-color: #ffebee;
        color: #b71c1c;
        border-color: #ef5350;
    }

    .section-title {
        margin-top: 10px;
        margin-bottom: 8px;
        font-size: 20px;
        font-weight: 700;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

st.title("NetSleuth IR")
st.subheader("Incident Response Packet Analyzer")


# ──────────────────────────────────────────────
# FIX 1: Human-readable timestamp helper
# ──────────────────────────────────────────────
def format_timestamp(ts):
    """Convert a raw Unix float timestamp to a readable datetime string."""
    if ts is None or (isinstance(ts, float) and ts != ts):  # NaN check
        return "N/A"
    try:
        return datetime.utcfromtimestamp(float(ts)).strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return str(ts)


def humanize_timestamps(df):
    """Return a copy of df with the timestamp column formatted as readable strings."""
    df2 = df.copy()
    if "timestamp" in df2.columns:
        df2["timestamp"] = df2["timestamp"].apply(format_timestamp)
    # Also convert start_ts / end_ts if present (sessions table)
    for col in ("start_ts", "end_ts"):
        if col in df2.columns:
            df2[col] = df2[col].apply(format_timestamp)
    return df2


def show_status(title, has_detection, clear_text, detected_text):
    st.markdown(f"<div class='section-title'>{title}</div>", unsafe_allow_html=True)
    if has_detection:
        st.markdown(
            f"<div class='status-box status-detected'>{detected_text}</div>",
            unsafe_allow_html=True,
        )
    else:
        st.markdown(
            f"<div class='status-box status-clear'>{clear_text}</div>",
            unsafe_allow_html=True,
        )


def build_bpf_filter(protocols, ip_value, port_value, custom_filter):
    parts = []
    if protocols:
        proto_clauses = []
        for proto in protocols:
            if proto == "dns":
                proto_clauses.append("port 53")
            elif proto == "http":
                proto_clauses.append("(tcp and (port 80 or port 8080 or port 8000))")
            else:
                proto_clauses.append(proto)
        parts.append("(" + " or ".join(proto_clauses) + ")")
    if ip_value:
        parts.append(f"host {ip_value.strip()}")
    if port_value:
        parts.append(f"port {int(port_value)}")
    if custom_filter:
        parts.append(f"({custom_filter.strip()})")
    return " and ".join(parts).strip()


def apply_packet_search_filters(
    df,
    src_ip_query,
    dst_ip_query,
    packet_protocols,
    app_protocols,
    port_query,
    payload_query,
    timestamp_min,
    timestamp_max,
):
    filtered = df.copy()
    if src_ip_query.strip():
        filtered = filtered[
            filtered["src_ip"].astype(str).str.contains(src_ip_query.strip(), case=False, na=False)
        ]
    if dst_ip_query.strip():
        filtered = filtered[
            filtered["dst_ip"].astype(str).str.contains(dst_ip_query.strip(), case=False, na=False)
        ]
    if packet_protocols:
        filtered = filtered[filtered["protocol"].isin(packet_protocols)]
    if app_protocols:
        filtered = filtered[filtered["app_protocol"].isin(app_protocols)]
    if port_query:
        filtered = filtered[
            (filtered["src_port"] == int(port_query)) | (filtered["dst_port"] == int(port_query))
        ]
    if payload_query.strip():
        filtered = filtered[
            filtered["payload_text"].astype(str).str.contains(payload_query.strip(), case=False, na=False)
        ]
    if timestamp_min is not None and timestamp_max is not None:
        filtered = filtered[
            filtered["timestamp"].notna()
            & (filtered["timestamp"] >= float(timestamp_min))
            & (filtered["timestamp"] <= float(timestamp_max))
        ]
    return filtered


# ──────────────────────────────────────────────
# FIX 2: Corrected severity enrichment thresholds
# ──────────────────────────────────────────────
def enrich_alert_severity(alert):
    enriched = dict(alert)
    alert_type = str(enriched.get("alert_type", "")).lower()
    severity = str(enriched.get("severity", "Low"))

    if "ddos" in alert_type and int(enriched.get("total_syn_packets", 0)) >= 200:
        severity = "Critical"
    elif "data exfiltration" in alert_type and int(enriched.get("total_bytes_sent", 0)) >= 100000:
        severity = "Critical"
    elif "port scanning" in alert_type:
        ports = int(enriched.get("unique_dst_ports", 0))
        if ports >= 100:
            severity = "Critical"
        elif ports >= 20:
            severity = "High"
        else:
            severity = "Medium"
    elif "icmp flood" in alert_type and int(enriched.get("icmp_count", 0)) >= 50:
        severity = "High"

    enriched["severity"] = severity
    return enriched


def run_detection_pipeline(df, arp_records):
    findings = []
    findings.extend(detect_port_scanning(df, port_threshold=5))
    findings.extend(detect_arp_spoofing(arp_records))
    findings.extend(detect_ddos(df, source_threshold=20, packet_threshold=50))
    findings.extend(detect_beaconing(df, min_connections=4, interval_tolerance=2.0))
    findings.extend(
        detect_unusual_outbound_connections(
            df,
            external_host_threshold=3,
            packet_threshold=5,
        )
    )
    findings.extend(detect_data_exfiltration(df, byte_threshold=10000))
    findings.extend(detect_icmp_flood(df, icmp_threshold=3))
    findings.extend(detect_icmp_sweep(df, target_threshold=5))
    findings.extend(detect_large_packets(df, size_threshold=1000))
    return [enrich_alert_severity(item) for item in findings]


def get_alert_key(alert):
    return "|".join(
        [
            str(alert.get("alert_type", "")),
            str(alert.get("src_ip", alert.get("ip", "N/A"))),
            str(alert.get("dst_ip", "N/A")),
            str(alert.get("dst_port", "N/A")),
        ]
    )


def update_realtime_alert_state(findings, now_ts, cooldown_sec=30, resolve_after_sec=30):
    state = st.session_state["rt_alert_state"]
    feed = st.session_state["rt_alert_feed"]
    last_notified = st.session_state["rt_last_notified"]
    current_keys = set()

    for finding in findings:
        key = get_alert_key(finding)
        current_keys.add(key)
        prev = state.get(key)
        first_seen = now_ts if prev is None else prev.get("first_seen", now_ts)
        status = "new" if prev is None or prev.get("status") == "resolved" else "ongoing"
        record = {
            **finding,
            "alert_key": key,
            "status": status,
            "first_seen": first_seen,
            "last_seen": now_ts,
        }
        state[key] = record
        can_notify = now_ts - float(last_notified.get(key, 0)) >= float(cooldown_sec)
        if status == "new" and can_notify:
            last_notified[key] = now_ts
            feed.insert(
                0,
                {
                    "timestamp": now_ts,
                    "event": "new",
                    "severity": record.get("severity", "Low"),
                    "alert_type": record.get("alert_type", "Unknown"),
                    "src_ip": record.get("src_ip", record.get("ip", "N/A")),
                    "dst_ip": record.get("dst_ip", "N/A"),
                    "reason": record.get("reason", ""),
                },
            )

    for key, record in list(state.items()):
        if key in current_keys:
            continue
        if record.get("status") == "resolved":
            continue
        stale_for = now_ts - float(record.get("last_seen", now_ts))
        if stale_for >= float(resolve_after_sec):
            record["status"] = "resolved"
            record["resolved_at"] = now_ts
            if now_ts - float(last_notified.get(f"{key}:resolved", 0)) >= float(cooldown_sec):
                last_notified[f"{key}:resolved"] = now_ts
                feed.insert(
                    0,
                    {
                        "timestamp": now_ts,
                        "event": "resolved",
                        "severity": record.get("severity", "Low"),
                        "alert_type": record.get("alert_type", "Unknown"),
                        "src_ip": record.get("src_ip", record.get("ip", "N/A")),
                        "dst_ip": record.get("dst_ip", "N/A"),
                        "reason": "Condition no longer detected in current window.",
                    },
                )

    st.session_state["rt_alert_feed"] = feed[:300]


# ──────────────────────────────────────────────
# FIX 3: Findings visualization charts
# ──────────────────────────────────────────────
SEVERITY_COLORS = {
    "Critical": "#b71c1c",
    "High":     "#e65100",
    "Medium":   "#f9a825",
    "Low":      "#2e7d32",
}

SEVERITY_ORDER = ["Critical", "High", "Medium", "Low"]


def render_findings_charts(findings):
    """Render three charts summarizing the findings."""
    findings_df = pd.DataFrame(findings)

    st.markdown("## Findings Overview")
    chart_col1, chart_col2 = st.columns(2)

    # ── Chart 1: Alerts by Type (horizontal bar) ──
    with chart_col1:
        st.markdown("### Alerts by Type")
        type_counts = findings_df["alert_type"].value_counts()
        fig1, ax1 = plt.subplots(figsize=(5, max(2.5, len(type_counts) * 0.55)))
        bars = ax1.barh(type_counts.index[::-1], type_counts.values[::-1], color="#1565c0", height=0.6)
        ax1.bar_label(bars, padding=4, fontsize=9)
        ax1.set_xlabel("Count", fontsize=9)
        ax1.tick_params(axis="y", labelsize=9)
        ax1.spines[["top", "right"]].set_visible(False)
        ax1.set_xlim(0, type_counts.max() * 1.25)
        plt.tight_layout()
        st.pyplot(fig1)
        plt.close(fig1)

    # ── Chart 2: Alerts by Severity (colour-coded bar) ──
    with chart_col2:
        st.markdown("### Alerts by Severity")
        sev_counts = findings_df["severity"].value_counts()
        ordered = [s for s in SEVERITY_ORDER if s in sev_counts.index]
        values  = [sev_counts[s] for s in ordered]
        colors  = [SEVERITY_COLORS.get(s, "#888") for s in ordered]

        fig2, ax2 = plt.subplots(figsize=(5, 2.8))
        bars2 = ax2.bar(ordered, values, color=colors, width=0.5)
        ax2.bar_label(bars2, padding=3, fontsize=9)
        ax2.set_ylabel("Count", fontsize=9)
        ax2.tick_params(axis="x", labelsize=9)
        ax2.spines[["top", "right"]].set_visible(False)
        ax2.set_ylim(0, max(values) * 1.3)
        plt.tight_layout()
        st.pyplot(fig2)
        plt.close(fig2)

    # ── Chart 3: Top offending source IPs ──
    if "src_ip" in findings_df.columns:
        ip_col = findings_df["src_ip"].fillna(
            findings_df.get("ip", pd.Series(dtype=str))
        )
        ip_counts = ip_col[ip_col != "N/A"].value_counts().head(8)

        if not ip_counts.empty:
            st.markdown("### Top Offending Source IPs")
            fig3, ax3 = plt.subplots(figsize=(8, max(2.5, len(ip_counts) * 0.55)))
            bars3 = ax3.barh(ip_counts.index[::-1], ip_counts.values[::-1], color="#c62828", height=0.6)
            ax3.bar_label(bars3, padding=4, fontsize=9)
            ax3.set_xlabel("Alert Count", fontsize=9)
            ax3.tick_params(axis="y", labelsize=9)
            ax3.spines[["top", "right"]].set_visible(False)
            ax3.set_xlim(0, ip_counts.max() * 1.25)
            plt.tight_layout()
            st.pyplot(fig3)
            plt.close(fig3)

    # ── Legend for severity colours ──
    patches = [
        mpatches.Patch(color=SEVERITY_COLORS[s], label=s)
        for s in SEVERITY_ORDER
        if s in findings_df.get("severity", pd.Series(dtype=str)).values
    ]
    if patches:
        fig_leg, ax_leg = plt.subplots(figsize=(4, 0.4))
        ax_leg.axis("off")
        ax_leg.legend(handles=patches, loc="center", ncol=len(patches),
                      frameon=False, fontsize=9)
        plt.tight_layout()
        st.pyplot(fig_leg)
        plt.close(fig_leg)


def analyze_packets(packets):
    packet_rows, arp_records = parse_pcap_packets(packets)
    base_df = pd.DataFrame(packet_rows)
    df, sessions_df = reconstruct_sessions(base_df, inactivity_timeout=60.0)

    st.markdown("## Traffic Summary")

    if df.empty:
        st.warning("No packets were found in this traffic capture.")
        return

    summary = get_traffic_summary(df)

    col1, col2, col3 = st.columns(3)
    col1.metric("Total Packets", summary["total_packets"])
    col2.metric("Unique Source IPs", summary["unique_source_ips"])
    col3.metric("Unique Destination IPs", summary["unique_destination_ips"])

    col4, col5, col6, col7, col8 = st.columns(5)
    col4.metric("TCP", summary["tcp_count"])
    col5.metric("UDP", summary["udp_count"])
    col6.metric("ICMP", summary["icmp_count"])
    col7.metric("ARP", summary["arp_count"])
    col8.metric("Other", summary["other_count"])

    st.markdown("### Protocol Counts")
    protocol_counts = df["protocol"].value_counts().reset_index()
    protocol_counts.columns = ["Protocol", "Count"]
    st.dataframe(protocol_counts, use_container_width=True)

    st.markdown("### Application Protocol Counts")
    app_protocol_counts = df["app_protocol"].fillna("Unknown").value_counts().reset_index()
    app_protocol_counts.columns = ["App Protocol", "Count"]
    st.dataframe(app_protocol_counts, use_container_width=True)

    st.markdown("### Protocol Distribution")
    fig, ax = plt.subplots()
    ax.bar(protocol_counts["Protocol"], protocol_counts["Count"])
    ax.set_xlabel("Protocol")
    ax.set_ylabel("Count")
    ax.set_title("Protocol Distribution")
    st.pyplot(fig)
    plt.close(fig)

    left, right = st.columns(2)
    with left:
        st.markdown("### Top Source IPs")
        top_src = (
            df[df["src_ip"] != "N/A"]["src_ip"]
            .value_counts()
            .head(10)
            .reset_index()
        )
        top_src.columns = ["Source IP", "Count"]
        st.dataframe(top_src, use_container_width=True)

    with right:
        st.markdown("### Top Destination IPs")
        top_dst = (
            df[df["dst_ip"] != "N/A"]["dst_ip"]
            .value_counts()
            .head(10)
            .reset_index()
        )
        top_dst.columns = ["Destination IP", "Count"]
        st.dataframe(top_dst, use_container_width=True)

    dns_df  = df[df["app_protocol"] == "DNS"].copy()
    http_df = df[df["app_protocol"] == "HTTP"].copy()

    st.markdown("## Deep Protocol Insights")
    proto_left, proto_right = st.columns(2)
    with proto_left:
        st.markdown("### Top DNS Queries")
        if not dns_df.empty and dns_df["dns_query"].notna().any():
            dns_top = dns_df[dns_df["dns_query"].notna()]["dns_query"].value_counts().head(10).reset_index()
            dns_top.columns = ["DNS Query", "Count"]
            st.dataframe(dns_top, use_container_width=True)
        else:
            st.caption("No DNS query records found.")

    with proto_right:
        st.markdown("### Top HTTP Hosts")
        if not http_df.empty and http_df["http_host"].notna().any():
            http_top = http_df[http_df["http_host"].notna()]["http_host"].value_counts().head(10).reset_index()
            http_top.columns = ["HTTP Host", "Count"]
            st.dataframe(http_top, use_container_width=True)
        else:
            st.caption("No HTTP host records found.")

    st.markdown("## Session Reconstruction")
    if sessions_df.empty:
        st.caption("No TCP/UDP sessions reconstructed from this traffic.")
    else:
        sess_col1, sess_col2, sess_col3 = st.columns(3)
        sess_col1.metric("Reconstructed Sessions", len(sessions_df))
        sess_col2.metric("TCP Sessions", int((sessions_df["protocol"] == "TCP").sum()))
        sess_col3.metric("UDP Sessions", int((sessions_df["protocol"] == "UDP").sum()))
        # FIX 1 applied: show human-readable timestamps in sessions table
        st.dataframe(humanize_timestamps(sessions_df).head(200), use_container_width=True)

    st.markdown("## Detection Results")

    portscan_results  = detect_port_scanning(df, port_threshold=5)
    arp_results       = detect_arp_spoofing(arp_records)
    ddos_results      = detect_ddos(df, source_threshold=20, packet_threshold=50)
    beacon_results    = detect_beaconing(df, min_connections=4, interval_tolerance=2.0)
    outbound_results  = detect_unusual_outbound_connections(df, external_host_threshold=3, packet_threshold=5)
    exfil_results     = detect_data_exfiltration(df, byte_threshold=10000)
    icmp_results      = detect_icmp_flood(df, icmp_threshold=3)
    icmp_sweep_results = detect_icmp_sweep(df, target_threshold=5)
    large_packet_results = detect_large_packets(df, size_threshold=1000)

    # Apply FIX 2 severity enrichment to each detector's results
    portscan_results     = [enrich_alert_severity(r) for r in portscan_results]
    ddos_results         = [enrich_alert_severity(r) for r in ddos_results]
    exfil_results        = [enrich_alert_severity(r) for r in exfil_results]
    icmp_results         = [enrich_alert_severity(r) for r in icmp_results]

    findings = []

    # Port Scan
    show_status(
        "Port Scan Detection",
        bool(portscan_results),
        "Clear: No possible port scanning detected.",
        "Detected: Possible port scanning activity found.",
    )
    if portscan_results:
        st.dataframe(pd.DataFrame(portscan_results), use_container_width=True)
        findings.extend(portscan_results)

    # ARP Spoofing
    show_status(
        "ARP Spoofing Detection",
        bool(arp_results),
        "Clear: No possible ARP spoofing detected.",
        "Detected: Possible ARP spoofing activity found.",
    )
    if arp_results:
        st.dataframe(pd.DataFrame(arp_results), use_container_width=True)
        findings.extend(arp_results)

    # DDoS
    show_status(
        "DDoS Detection",
        bool(ddos_results),
        "Clear: No possible DDoS-like traffic detected.",
        "Detected: Possible DDoS-like traffic found.",
    )
    if ddos_results:
        st.dataframe(pd.DataFrame(ddos_results), use_container_width=True)
        findings.extend(ddos_results)

    # Beaconing
    show_status(
        "Beaconing Detection",
        bool(beacon_results),
        "Clear: No possible beaconing detected.",
        "Detected: Possible beaconing activity found.",
    )
    if beacon_results:
        st.dataframe(pd.DataFrame(beacon_results), use_container_width=True)
        findings.extend(beacon_results)

    # Unusual Outbound
    show_status(
        "Unusual Outbound Connections",
        bool(outbound_results),
        "Clear: No unusual outbound connections detected.",
        "Detected: Possible unusual outbound connections found.",
    )
    if outbound_results:
        st.dataframe(pd.DataFrame(outbound_results), use_container_width=True)
        findings.extend(outbound_results)

    # Data Exfiltration
    show_status(
        "Data Exfiltration Detection",
        bool(exfil_results),
        "Clear: No possible data exfiltration detected.",
        "Detected: Possible data exfiltration activity found.",
    )
    if exfil_results:
        st.dataframe(pd.DataFrame(exfil_results), use_container_width=True)
        findings.extend(exfil_results)

    # ICMP Flood
    show_status(
        "ICMP Flood Detection",
        bool(icmp_results),
        "Clear: No possible ICMP flood detected.",
        "Detected: Possible ICMP flood activity found.",
    )
    if icmp_results:
        st.dataframe(pd.DataFrame(icmp_results), use_container_width=True)
        findings.extend(icmp_results)

    # ICMP Sweep
    show_status(
        "ICMP Sweep Detection",
        bool(icmp_sweep_results),
        "Clear: No possible ICMP sweep detected.",
        "Detected: Possible ICMP sweep activity found.",
    )
    if icmp_sweep_results:
        st.dataframe(pd.DataFrame(icmp_sweep_results), use_container_width=True)
        findings.extend(icmp_sweep_results)

    # Large Packets
    show_status(
        "Large Packet Detection",
        bool(large_packet_results),
        "Clear: No unusually large packets detected.",
        "Detected: Large packets found.",
    )
    if large_packet_results:
        st.dataframe(pd.DataFrame(large_packet_results[:20]), use_container_width=True)
        findings.extend(large_packet_results)

    # ── FIX 3: Findings visualization charts (before the raw table) ──
    if findings:
        render_findings_charts(findings)

    st.markdown("## Findings Report")
    if findings:
        findings_df = pd.DataFrame(findings)
        st.dataframe(findings_df, use_container_width=True)
        csv = findings_df.to_csv(index=False).encode("utf-8")
        st.download_button(
            label="Download Findings Report as CSV",
            data=csv,
            file_name="netsleuth_findings_report.csv",
            mime="text/csv",
        )
    else:
        st.markdown(
            "<div class='status-box status-clear'>Overall Status: No suspicious activity detected using current rules.</div>",
            unsafe_allow_html=True,
        )

    st.markdown("## Parsed Packet Data")
    # FIX 1 applied: human-readable timestamps in parsed packet table
    st.dataframe(humanize_timestamps(df).head(200), use_container_width=True)

    st.markdown("## Investigation Tools")
    with st.expander("Packet Search & Filtering", expanded=True):
        fcol1, fcol2, fcol3 = st.columns(3)

        src_ip_query = fcol1.text_input("Source IP contains", value="")
        dst_ip_query = fcol2.text_input("Destination IP contains", value="")
        port_query   = fcol3.number_input(
            "Port equals (optional)", min_value=0, max_value=65535, value=0, step=1,
        )

        packet_protocols = st.multiselect(
            "Packet protocols",
            sorted(df["protocol"].dropna().astype(str).unique().tolist()),
            default=[],
        )
        app_protocols = st.multiselect(
            "Application protocols",
            sorted(df["app_protocol"].dropna().astype(str).unique().tolist()),
            default=[],
        )
        payload_query = st.text_input("Payload contains (text)", value="")

        ts_min = None
        ts_max = None
        ts_df = df[df["timestamp"].notna()]
        if not ts_df.empty:
            min_ts = float(ts_df["timestamp"].min())
            max_ts = float(ts_df["timestamp"].max())
            if max_ts > min_ts:
                ts_min, ts_max = st.slider(
                    "Timestamp range",
                    min_value=min_ts,
                    max_value=max_ts,
                    value=(min_ts, max_ts),
                    format="%.2f",
                    help="Drag to filter packets by time. Hover to see Unix timestamp.",
                )
                # Show human-readable labels below the slider
                sl_col1, sl_col2 = st.columns(2)
                sl_col1.caption(f"From: {format_timestamp(ts_min)}")
                sl_col2.caption(f"To:   {format_timestamp(ts_max)}")
            else:
                ts_min, ts_max = min_ts, max_ts

        searched_df = apply_packet_search_filters(
            df=df,
            src_ip_query=src_ip_query,
            dst_ip_query=dst_ip_query,
            packet_protocols=packet_protocols,
            app_protocols=app_protocols,
            port_query=port_query,
            payload_query=payload_query,
            timestamp_min=ts_min,
            timestamp_max=ts_max,
        )

        st.write(f"Matching packets: {len(searched_df)}")
        # FIX 1 applied: human-readable timestamps in search results
        st.dataframe(humanize_timestamps(searched_df).head(500), use_container_width=True)

    with st.expander("Payload Inspection", expanded=False):
        payload_candidates = searched_df if "searched_df" in locals() else df
        payload_candidates = payload_candidates[payload_candidates["payload_size"] > 0]

        if payload_candidates.empty:
            st.caption("No packets with payload available for inspection.")
        else:
            selected_packet_no = st.selectbox(
                "Select packet number",
                payload_candidates["packet_no"].astype(int).tolist(),
            )
            selected_row = payload_candidates[
                payload_candidates["packet_no"] == selected_packet_no
            ].iloc[0]

            st.write(
                "Packet:",
                f"#{int(selected_row['packet_no'])} "
                f"{selected_row['src_ip']}:{selected_row['src_port']} -> "
                f"{selected_row['dst_ip']}:{selected_row['dst_port']}",
            )
            # FIX 1: show readable timestamp for selected packet
            st.write("Timestamp:", format_timestamp(selected_row.get("timestamp")))
            st.write("App protocol:", selected_row.get("app_protocol", "Unknown"))
            st.write("Payload size:", int(selected_row.get("payload_size", 0)), "bytes")
            st.text_area(
                "Payload Text (truncated)",
                value=str(selected_row.get("payload_text", "")),
                height=180,
            )
            st.text_area(
                "Payload Hex (truncated)",
                value=str(selected_row.get("payload_hex", "")),
                height=140,
            )

    with st.expander("Follow TCP Stream", expanded=False):
        tcp_sessions = sessions_df[sessions_df["protocol"] == "TCP"] if not sessions_df.empty else pd.DataFrame()
        if tcp_sessions.empty:
            st.caption("No TCP sessions found for stream following.")
        else:
            selected_session_id = st.selectbox(
                "Select TCP session",
                tcp_sessions["session_id"].tolist(),
            )
            direction = st.radio(
                "Direction",
                ["Both", "A->B", "B->A"],
                horizontal=True,
            )

            stream_df = df[
                (df["session_id"] == selected_session_id) & (df["protocol"] == "TCP")
            ].copy()
            if direction == "A->B":
                stream_df = stream_df[stream_df["stream_direction"] == "A->B"]
            elif direction == "B->A":
                stream_df = stream_df[stream_df["stream_direction"] == "B->A"]

            stream_df = stream_df.sort_values(by=["timestamp", "packet_no"])
            stream_payload_rows = stream_df[stream_df["payload_size"] > 0][
                ["packet_no", "timestamp", "src_ip", "src_port", "dst_ip", "dst_port", "payload_text"]
            ].copy()

            # FIX 1: human-readable timestamps in stream view
            stream_payload_rows["timestamp"] = stream_payload_rows["timestamp"].apply(format_timestamp)

            if stream_payload_rows.empty:
                st.caption("No payload data available in the selected stream/direction.")
            else:
                st.dataframe(stream_payload_rows.head(300), use_container_width=True)
                combined_text = "\n".join(
                    [
                        (
                            f"[pkt {int(row['packet_no'])}] "
                            f"{row['src_ip']}:{row['src_port']} -> {row['dst_ip']}:{row['dst_port']}\n"
                            f"{row['payload_text']}"
                        )
                        for _, row in stream_payload_rows.iterrows()
                    ]
                )
                st.text_area("Reassembled Stream View (text)", value=combined_text, height=260)


# ── Session state init ──
for key, default in {
    "captured_packets": None,
    "captured_pcap_bytes": None,
    "captured_meta": {},
    "rt_monitoring": False,
    "rt_packet_rows": [],
    "rt_arp_records": [],
    "rt_alert_state": {},
    "rt_alert_feed": [],
    "rt_last_notified": {},
    "rt_config": {},
}.items():
    if key not in st.session_state:
        st.session_state[key] = default

input_mode = st.radio(
    "Choose Traffic Source",
    ["Upload PCAP", "Live Capture"],
    horizontal=True,
)

packets_to_analyze = None

if input_mode == "Upload PCAP":
    uploaded_file = st.file_uploader(
        "Upload a PCAP file",
        type=["pcap", "cap", "pcapng"],
    )

    if uploaded_file is not None:
        st.success("PCAP file uploaded successfully.")
        st.write("Filename:", uploaded_file.name)
        st.write("File size:", uploaded_file.size, "bytes")

        with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as tmp:
            tmp.write(uploaded_file.read())
            tmp_path = tmp.name

        try:
            packets_to_analyze = rdpcap(tmp_path)
        except Exception as e:
            st.error(f"Error reading PCAP file: {e}")
        finally:
            try:
                os.remove(tmp_path)
            except OSError:
                pass
    else:
        st.info("Please upload a .pcap file to begin analysis.")

else:
    st.markdown("### Live Capture")
    st.caption("Tip: Live capture may require elevated permissions on your system.")

    try:
        interfaces = get_if_list()
    except Exception:
        interfaces = []

    selected_interface = st.selectbox(
        "Select network interface",
        interfaces if interfaces else ["No interfaces found"],
        index=0,
    )

    col1, col2 = st.columns(2)
    capture_seconds = col1.number_input(
        "Capture duration (seconds)", min_value=1, max_value=300, value=10, step=1,
    )
    packet_limit = col2.number_input(
        "Max packets (0 = unlimited)", min_value=0, max_value=100000, value=500, step=50,
    )

    st.markdown("#### Capture Filters")
    f1, f2, f3 = st.columns(3)
    protocol_filter = f1.multiselect(
        "Protocol filter", ["tcp", "udp", "icmp", "arp", "dns", "http"], default=[],
    )
    ip_filter    = f2.text_input("IP/Host filter", value="", placeholder="e.g. 192.168.1.5")
    port_filter  = f3.number_input("Port filter", min_value=0, max_value=65535, value=0, step=1)

    capture_filter = st.text_input("Custom BPF filter (optional)", placeholder="e.g. tcp and port 443")
    final_capture_filter = build_bpf_filter(
        protocols=protocol_filter, ip_value=ip_filter,
        port_value=port_filter, custom_filter=capture_filter,
    )
    st.caption(
        f"Effective filter: {final_capture_filter if final_capture_filter else 'None (capture all traffic)'}"
    )

    save_capture = st.checkbox("Save captured packets for download", value=True)

    if st.button("Start Live Capture", type="primary"):
        if not interfaces:
            st.error("No network interface is available for live capture.")
        else:
            try:
                sniff_kwargs = {"iface": selected_interface, "timeout": int(capture_seconds)}
                if int(packet_limit) > 0:
                    sniff_kwargs["count"] = int(packet_limit)
                if final_capture_filter:
                    sniff_kwargs["filter"] = final_capture_filter

                with st.spinner("Capturing packets..."):
                    captured_packets = sniff(**sniff_kwargs)

                st.session_state["captured_packets"] = captured_packets
                st.session_state["captured_meta"] = {
                    "interface": selected_interface,
                    "seconds": int(capture_seconds),
                    "packet_count": len(captured_packets),
                    "filter": final_capture_filter or "None",
                }
                st.session_state["captured_pcap_bytes"] = None

                if save_capture and len(captured_packets) > 0:
                    with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as tmp:
                        temp_capture_path = tmp.name
                    wrpcap(temp_capture_path, captured_packets)
                    with open(temp_capture_path, "rb") as pcap_file:
                        st.session_state["captured_pcap_bytes"] = pcap_file.read()
                    try:
                        os.remove(temp_capture_path)
                    except OSError:
                        pass

            except PermissionError:
                st.error(
                    "Permission denied while capturing live traffic. "
                    "Try running Streamlit with elevated privileges."
                )
            except Exception as e:
                st.error(f"Live capture failed: {e}")

    if st.session_state["captured_packets"] is not None:
        metadata = st.session_state["captured_meta"]
        st.success("Live capture completed successfully.")
        st.write("Interface:", metadata.get("interface", "N/A"))
        st.write("Capture duration:", metadata.get("seconds", 0), "seconds")
        st.write("Captured packets:", metadata.get("packet_count", 0))
        st.write("Filter:", metadata.get("filter", "None"))

        if st.session_state["captured_pcap_bytes"] is not None:
            st.download_button(
                label="Download Captured PCAP",
                data=st.session_state["captured_pcap_bytes"],
                file_name="netsleuth_live_capture.pcap",
                mime="application/vnd.tcpdump.pcap",
            )
        packets_to_analyze = st.session_state["captured_packets"]
    else:
        st.info("Configure live capture options, then click 'Start Live Capture'.")

    st.markdown("### Real-Time Alert Monitoring")
    st.caption(
        "Continuously captures traffic in short intervals and evaluates alerts "
        "on a rolling time window."
    )

    rt_col1, rt_col2, rt_col3 = st.columns(3)
    rt_poll_seconds    = rt_col1.number_input("Polling interval (seconds)",  min_value=1, max_value=10,  value=2,  step=1,  key="rt_poll_seconds")
    rt_window_seconds  = rt_col2.number_input("Analysis window (seconds)",   min_value=10, max_value=300, value=30, step=5,  key="rt_window_seconds")
    rt_cooldown_seconds = rt_col3.number_input("Alert cooldown (seconds)",   min_value=5, max_value=180, value=30, step=5,  key="rt_cooldown_seconds")

    rt_controls_left, rt_controls_right = st.columns(2)
    start_rt = rt_controls_left.button("Start Real-Time Monitoring", type="primary")
    stop_rt  = rt_controls_right.button("Stop Real-Time Monitoring")

    if start_rt:
        st.session_state["rt_monitoring"]    = True
        st.session_state["rt_packet_rows"]   = []
        st.session_state["rt_arp_records"]   = []
        st.session_state["rt_alert_state"]   = {}
        st.session_state["rt_alert_feed"]    = []
        st.session_state["rt_last_notified"] = {}
        st.session_state["rt_config"] = {
            "interface": selected_interface,
            "filter": final_capture_filter,
            "poll_seconds": int(rt_poll_seconds),
            "window_seconds": int(rt_window_seconds),
            "cooldown_seconds": int(rt_cooldown_seconds),
        }

    if stop_rt:
        st.session_state["rt_monitoring"] = False

    if st.session_state["rt_monitoring"]:
        rt_config = st.session_state["rt_config"] or {
            "interface": selected_interface,
            "filter": final_capture_filter,
            "poll_seconds": int(rt_poll_seconds),
            "window_seconds": int(rt_window_seconds),
            "cooldown_seconds": int(rt_cooldown_seconds),
        }
        st.warning(
            f"Real-time monitoring active on `{rt_config['interface']}`. "
            f"Window: {rt_config['window_seconds']}s, Poll: {rt_config['poll_seconds']}s."
        )

        try:
            sniff_kwargs = {
                "iface": rt_config["interface"],
                "timeout": int(rt_config["poll_seconds"]),
                "store": True,
            }
            if rt_config.get("filter"):
                sniff_kwargs["filter"] = rt_config["filter"]

            captured_chunk = sniff(**sniff_kwargs)
            chunk_rows, chunk_arp = parse_pcap_packets(captured_chunk)
            now_ts = time.time()

            st.session_state["rt_packet_rows"].extend(chunk_rows)
            st.session_state["rt_arp_records"].extend(chunk_arp)

            cutoff = now_ts - float(rt_config["window_seconds"])
            st.session_state["rt_packet_rows"] = [
                row for row in st.session_state["rt_packet_rows"]
                if row.get("timestamp") is None or float(row.get("timestamp", now_ts)) >= cutoff
            ]
            st.session_state["rt_arp_records"] = [
                row for row in st.session_state["rt_arp_records"]
                if row.get("timestamp") is None or float(row.get("timestamp", now_ts)) >= cutoff
            ]

            rt_df = pd.DataFrame(st.session_state["rt_packet_rows"])
            realtime_findings = run_detection_pipeline(rt_df, st.session_state["rt_arp_records"]) if not rt_df.empty else []

            update_realtime_alert_state(
                findings=realtime_findings,
                now_ts=now_ts,
                cooldown_sec=rt_config["cooldown_seconds"],
                resolve_after_sec=rt_config["window_seconds"],
            )

            alert_state  = st.session_state["rt_alert_state"]
            active_alerts = [a for a in alert_state.values() if a.get("status") in ("new", "ongoing")]
            active_df    = pd.DataFrame(active_alerts)
            feed_df      = pd.DataFrame(st.session_state["rt_alert_feed"])

            m1, m2, m3 = st.columns(3)
            m1.metric("Window Packets", len(st.session_state["rt_packet_rows"]))
            m2.metric("Active Alerts",  len(active_alerts))
            m3.metric("Total Alert Events", len(st.session_state["rt_alert_feed"]))

            if not feed_df.empty:
                # FIX 1: human-readable timestamps in RT alert feed
                feed_df["timestamp"] = feed_df["timestamp"].apply(format_timestamp)
                st.markdown("#### Alert Feed")
                st.dataframe(feed_df.head(100), use_container_width=True)
            else:
                st.caption("No alert events yet.")

            if not active_df.empty:
                cols = [c for c in ["severity","status","alert_type","src_ip","dst_ip","reason","first_seen","last_seen"] if c in active_df.columns]
                active_df = active_df[cols]
                # FIX 1: human-readable timestamps in RT active alerts
                for tc in ("first_seen", "last_seen"):
                    if tc in active_df.columns:
                        active_df[tc] = active_df[tc].apply(format_timestamp)
                st.markdown("#### Active Alerts")
                st.dataframe(active_df, use_container_width=True)
            else:
                st.caption("No active alerts in the current time window.")

            time.sleep(0.1)
            st.rerun()

        except PermissionError:
            st.session_state["rt_monitoring"] = False
            st.error("Permission denied while monitoring live traffic. Try running Streamlit with elevated privileges.")
        except Exception as e:
            st.session_state["rt_monitoring"] = False
            st.error(f"Real-time monitoring failed: {e}")

if packets_to_analyze is not None:
    try:
        analyze_packets(packets_to_analyze)
    except Exception as e:
        st.error(f"Error analyzing traffic: {e}")