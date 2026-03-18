import tempfile
import pandas as pd
import streamlit as st
import matplotlib.pyplot as plt
from scapy.all import rdpcap

from detectors import (
    parse_pcap_packets,
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

uploaded_file = st.file_uploader("Upload a PCAP file", type=["pcap", "cap", "pcapng"])


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


if uploaded_file is not None:
    st.success("PCAP file uploaded successfully.")
    st.write("Filename:", uploaded_file.name)
    st.write("File size:", uploaded_file.size, "bytes")

    with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as tmp:
        tmp.write(uploaded_file.read())
        tmp_path = tmp.name

    try:
        packets = rdpcap(tmp_path)

        packet_rows, arp_records = parse_pcap_packets(packets)
        df = pd.DataFrame(packet_rows)

        st.markdown("## Traffic Summary")

        if df.empty:
            st.warning("No packets were found in this PCAP file.")
        else:
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

            st.markdown("### Protocol Distribution")
            fig, ax = plt.subplots()
            ax.bar(protocol_counts["Protocol"], protocol_counts["Count"])
            ax.set_xlabel("Protocol")
            ax.set_ylabel("Count")
            ax.set_title("Protocol Distribution")
            st.pyplot(fig)

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

            st.markdown("## Detection Results")

            portscan_results = detect_port_scanning(df, port_threshold=5)
            arp_results = detect_arp_spoofing(arp_records)
            ddos_results = detect_ddos(df, source_threshold=20, packet_threshold=50)
            beacon_results = detect_beaconing(df, min_connections=4, interval_tolerance=2.0)
            outbound_results = detect_unusual_outbound_connections(
                df,
                external_host_threshold=3,
                packet_threshold=5,
            )
            exfil_results = detect_data_exfiltration(df, byte_threshold=10000)
            icmp_results = detect_icmp_flood(df, icmp_threshold=3)
            icmp_sweep_results = detect_icmp_sweep(df, target_threshold=5)
            large_packet_results = detect_large_packets(df, size_threshold=1000)

            findings = []

            # Port Scan
            show_status(
                "Port Scan Detection",
                bool(portscan_results),
                "Clear: No possible port scanning detected.",
                "Detected: Possible port scanning activity found.",
            )
            if portscan_results:
                portscan_df = pd.DataFrame(portscan_results)
                st.dataframe(portscan_df, use_container_width=True)
                findings.extend(portscan_results)

            # ARP Spoofing
            show_status(
                "ARP Spoofing Detection",
                bool(arp_results),
                "Clear: No possible ARP spoofing detected.",
                "Detected: Possible ARP spoofing activity found.",
            )
            if arp_results:
                arp_df = pd.DataFrame(arp_results)
                st.dataframe(arp_df, use_container_width=True)
                findings.extend(arp_results)

            # DDoS
            show_status(
                "DDoS Detection",
                bool(ddos_results),
                "Clear: No possible DDoS-like traffic detected.",
                "Detected: Possible DDoS-like traffic found.",
            )
            if ddos_results:
                ddos_df = pd.DataFrame(ddos_results)
                st.dataframe(ddos_df, use_container_width=True)
                findings.extend(ddos_results)

            # Beaconing
            show_status(
                "Beaconing Detection",
                bool(beacon_results),
                "Clear: No possible beaconing detected.",
                "Detected: Possible beaconing activity found.",
            )
            if beacon_results:
                beacon_df = pd.DataFrame(beacon_results)
                st.dataframe(beacon_df, use_container_width=True)
                findings.extend(beacon_results)

            # Unusual Outbound
            show_status(
                "Unusual Outbound Connections",
                bool(outbound_results),
                "Clear: No unusual outbound connections detected.",
                "Detected: Possible unusual outbound connections found.",
            )
            if outbound_results:
                outbound_df = pd.DataFrame(outbound_results)
                st.dataframe(outbound_df, use_container_width=True)
                findings.extend(outbound_results)

            # Data Exfiltration
            show_status(
                "Data Exfiltration Detection",
                bool(exfil_results),
                "Clear: No possible data exfiltration detected.",
                "Detected: Possible data exfiltration activity found.",
            )
            if exfil_results:
                exfil_df = pd.DataFrame(exfil_results)
                st.dataframe(exfil_df, use_container_width=True)
                findings.extend(exfil_results)

            # ICMP Flood
            show_status(
                "ICMP Flood Detection",
                bool(icmp_results),
                "Clear: No possible ICMP flood detected.",
                "Detected: Possible ICMP flood activity found.",
            )
            if icmp_results:
                icmp_df = pd.DataFrame(icmp_results)
                st.dataframe(icmp_df, use_container_width=True)
                findings.extend(icmp_results)

            # ICMP Sweep
            show_status(
                "ICMP Sweep Detection",
                bool(icmp_sweep_results),
                "Clear: No possible ICMP sweep detected.",
                "Detected: Possible ICMP sweep activity found.",
            )
            if icmp_sweep_results:
                icmp_sweep_df = pd.DataFrame(icmp_sweep_results)
                st.dataframe(icmp_sweep_df, use_container_width=True)
                findings.extend(icmp_sweep_results)

            # Large Packets
            show_status(
                "Large Packet Detection",
                bool(large_packet_results),
                "Clear: No unusually large packets detected.",
                "Detected: Large packets found.",
            )
            if large_packet_results:
                large_df = pd.DataFrame(large_packet_results[:20])
                st.dataframe(large_df, use_container_width=True)
                findings.extend(large_packet_results)

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
            st.dataframe(df.head(200), use_container_width=True)

    except Exception as e:
        st.error(f"Error reading PCAP file: {e}")

else:
    st.info("Please upload a .pcap file to begin analysis.")