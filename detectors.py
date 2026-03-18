from collections import defaultdict
from statistics import pstdev
from scapy.all import IP, TCP, UDP, ICMP, ARP, DNS, DNSQR, Raw
import pandas as pd


def is_internal_ip(ip):
    if not isinstance(ip, str):
        return False

    return (
        ip.startswith("10.")
        or ip.startswith("192.168.")
        or ip.startswith("172.16.")
        or ip.startswith("172.17.")
        or ip.startswith("172.18.")
        or ip.startswith("172.19.")
        or ip.startswith("172.20.")
        or ip.startswith("172.21.")
        or ip.startswith("172.22.")
        or ip.startswith("172.23.")
        or ip.startswith("172.24.")
        or ip.startswith("172.25.")
        or ip.startswith("172.26.")
        or ip.startswith("172.27.")
        or ip.startswith("172.28.")
        or ip.startswith("172.29.")
        or ip.startswith("172.30.")
        or ip.startswith("172.31.")
    )


def parse_pcap_packets(packets):
    packets_data = []
    arp_records = []

    for i, pkt in enumerate(packets, start=1):
        src_ip = "N/A"
        dst_ip = "N/A"
        protocol = "Other"
        src_port = None
        dst_port = None
        tcp_flags = None
        icmp_type = None
        length = len(pkt)
        timestamp = float(pkt.time) if hasattr(pkt, "time") else None
        app_protocol = "Unknown"
        dns_query = None
        dns_rcode = None
        dns_is_response = None
        http_method = None
        http_host = None
        http_uri = None
        http_status = None
        payload_size = 0
        payload_text = ""
        payload_hex = ""

        if ARP in pkt:
            protocol = "ARP"
            app_protocol = "ARP"
            src_ip = pkt[ARP].psrc
            dst_ip = pkt[ARP].pdst

            if pkt[ARP].op == 2:
                arp_records.append(
                    {
                        "ip": pkt[ARP].psrc,
                        "mac": pkt[ARP].hwsrc,
                        "timestamp": timestamp,
                    }
                )

        elif IP in pkt:
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst

            if TCP in pkt:
                protocol = "TCP"
                app_protocol = "TCP"
                src_port = pkt[TCP].sport
                dst_port = pkt[TCP].dport
                tcp_flags = str(pkt[TCP].flags)

            elif UDP in pkt:
                protocol = "UDP"
                app_protocol = "UDP"
                src_port = pkt[UDP].sport
                dst_port = pkt[UDP].dport

            elif ICMP in pkt:
                protocol = "ICMP"
                app_protocol = "ICMP"
                icmp_type = int(pkt[ICMP].type)

            else:
                protocol = "IP"
                app_protocol = "IP"

            if DNS in pkt:
                app_protocol = "DNS"
                dns_layer = pkt[DNS]
                dns_is_response = bool(getattr(dns_layer, "qr", 0))
                dns_rcode = int(getattr(dns_layer, "rcode", 0))
                if DNSQR in dns_layer:
                    qname = dns_layer[DNSQR].qname
                    if isinstance(qname, bytes):
                        dns_query = qname.decode(errors="replace").rstrip(".")
                    else:
                        dns_query = str(qname).rstrip(".")

            if Raw in pkt:
                raw_payload = bytes(pkt[Raw].load)
                payload_size = len(raw_payload)
                payload_text = raw_payload[:512].decode(errors="replace")
                payload_hex = raw_payload[:256].hex()

                if protocol == "TCP":
                    text = payload_text
                    upper_text = text.upper()
                    http_methods = (
                        "GET ",
                        "POST ",
                        "PUT ",
                        "DELETE ",
                        "HEAD ",
                        "OPTIONS ",
                        "PATCH ",
                    )

                    if any(upper_text.startswith(method) for method in http_methods):
                        app_protocol = "HTTP"
                        first_line = text.splitlines()[0] if text.splitlines() else ""
                        parts = first_line.split(" ")
                        if len(parts) >= 2:
                            http_method = parts[0]
                            http_uri = parts[1]

                        for line in text.splitlines():
                            if line.lower().startswith("host:"):
                                http_host = line.split(":", 1)[1].strip()
                                break

                    elif upper_text.startswith("HTTP/"):
                        app_protocol = "HTTP"
                        first_line = text.splitlines()[0] if text.splitlines() else ""
                        parts = first_line.split(" ")
                        if len(parts) >= 2:
                            http_status = parts[1]
                    elif src_port == 443 or dst_port == 443:
                        app_protocol = "HTTPS"
                    elif src_port in (80, 8080, 8000) or dst_port in (80, 8080, 8000):
                        app_protocol = "HTTP"

        packets_data.append(
            {
                "packet_no": i,
                "timestamp": timestamp,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "protocol": protocol,
                "src_port": src_port,
                "dst_port": dst_port,
                "tcp_flags": tcp_flags,
                "icmp_type": icmp_type,
                "length": length,
                "app_protocol": app_protocol,
                "dns_query": dns_query,
                "dns_rcode": dns_rcode,
                "dns_is_response": dns_is_response,
                "http_method": http_method,
                "http_host": http_host,
                "http_uri": http_uri,
                "http_status": http_status,
                "payload_size": payload_size,
                "payload_text": payload_text,
                "payload_hex": payload_hex,
            }
        )

    return packets_data, arp_records


def reconstruct_sessions(df, inactivity_timeout=60.0):
    if df.empty:
        return df.copy(), pd.DataFrame()

    session_df = df.copy()
    session_df["session_id"] = None
    session_df["conversation_key"] = None
    session_df["stream_direction"] = None

    sortable_df = session_df.copy()
    sortable_df["sort_ts"] = sortable_df["timestamp"].fillna(-1)
    sortable_df = sortable_df.sort_values(by=["sort_ts", "packet_no"])

    active_conversations = {}
    session_records = {}
    session_counter = 0

    for idx, row in sortable_df.iterrows():
        protocol = row.get("protocol")
        src_ip = row.get("src_ip")
        dst_ip = row.get("dst_ip")
        src_port = row.get("src_port")
        dst_port = row.get("dst_port")
        timestamp = row.get("timestamp")
        length = int(row.get("length", 0))
        app_protocol = row.get("app_protocol", "Unknown")
        tcp_flags = row.get("tcp_flags")

        valid_ports = pd.notna(src_port) and pd.notna(dst_port)
        valid_hosts = src_ip != "N/A" and dst_ip != "N/A"
        if protocol not in ("TCP", "UDP") or not valid_ports or not valid_hosts:
            continue

        endpoint_a = (str(src_ip), int(src_port))
        endpoint_b = (str(dst_ip), int(dst_port))
        if endpoint_a <= endpoint_b:
            canonical_a = endpoint_a
            canonical_b = endpoint_b
            direction = "A->B"
        else:
            canonical_a = endpoint_b
            canonical_b = endpoint_a
            direction = "B->A"

        conversation_key = (
            f"{protocol}:{canonical_a[0]}:{canonical_a[1]}"
            f"<->{canonical_b[0]}:{canonical_b[1]}"
        )

        session_id = None
        if conversation_key in active_conversations:
            current_session_id = active_conversations[conversation_key]
            last_seen = session_records[current_session_id]["last_seen"]
            if timestamp is None or last_seen is None:
                session_id = current_session_id
            elif float(timestamp) - float(last_seen) <= float(inactivity_timeout):
                session_id = current_session_id

        if session_id is None:
            session_counter += 1
            session_id = f"S{session_counter:05d}"
            session_records[session_id] = {
                "session_id": session_id,
                "protocol": protocol,
                "conversation_key": conversation_key,
                "endpoint_a_ip": canonical_a[0],
                "endpoint_a_port": canonical_a[1],
                "endpoint_b_ip": canonical_b[0],
                "endpoint_b_port": canonical_b[1],
                "start_ts": timestamp,
                "end_ts": timestamp,
                "last_seen": timestamp,
                "total_packets": 0,
                "total_bytes": 0,
                "a_to_b_packets": 0,
                "b_to_a_packets": 0,
                "a_to_b_bytes": 0,
                "b_to_a_bytes": 0,
                "app_protocols": set(),
                "tcp_flags_seen": set(),
            }
            active_conversations[conversation_key] = session_id

        session_df.at[idx, "session_id"] = session_id
        session_df.at[idx, "conversation_key"] = conversation_key
        session_df.at[idx, "stream_direction"] = direction

        record = session_records[session_id]
        record["total_packets"] += 1
        record["total_bytes"] += length
        record["end_ts"] = timestamp
        record["last_seen"] = timestamp
        if direction == "A->B":
            record["a_to_b_packets"] += 1
            record["a_to_b_bytes"] += length
        else:
            record["b_to_a_packets"] += 1
            record["b_to_a_bytes"] += length
        if isinstance(app_protocol, str) and app_protocol:
            record["app_protocols"].add(app_protocol)
        if pd.notna(tcp_flags):
            record["tcp_flags_seen"].add(str(tcp_flags))

    sessions = []
    for data in session_records.values():
        start_ts = data["start_ts"]
        end_ts = data["end_ts"]
        duration_sec = None
        if start_ts is not None and end_ts is not None:
            duration_sec = max(0.0, float(end_ts) - float(start_ts))

        sessions.append(
            {
                "session_id": data["session_id"],
                "protocol": data["protocol"],
                "conversation_key": data["conversation_key"],
                "endpoint_a": f"{data['endpoint_a_ip']}:{data['endpoint_a_port']}",
                "endpoint_b": f"{data['endpoint_b_ip']}:{data['endpoint_b_port']}",
                "start_ts": start_ts,
                "end_ts": end_ts,
                "duration_sec": round(duration_sec, 3) if duration_sec is not None else None,
                "total_packets": data["total_packets"],
                "total_bytes": data["total_bytes"],
                "a_to_b_packets": data["a_to_b_packets"],
                "b_to_a_packets": data["b_to_a_packets"],
                "a_to_b_bytes": data["a_to_b_bytes"],
                "b_to_a_bytes": data["b_to_a_bytes"],
                "app_protocols": ", ".join(sorted(data["app_protocols"])),
                "tcp_flags_seen": ", ".join(sorted(data["tcp_flags_seen"])),
            }
        )

    sessions_df = pd.DataFrame(sessions).sort_values(
        by=["total_packets", "total_bytes"],
        ascending=False,
    ) if sessions else pd.DataFrame()

    return session_df, sessions_df


def get_traffic_summary(df):
    protocol_counts = df["protocol"].value_counts().to_dict()

    return {
        "total_packets": len(df),
        "unique_source_ips": df[df["src_ip"] != "N/A"]["src_ip"].nunique(),
        "unique_destination_ips": df[df["dst_ip"] != "N/A"]["dst_ip"].nunique(),
        "tcp_count": protocol_counts.get("TCP", 0),
        "udp_count": protocol_counts.get("UDP", 0),
        "icmp_count": protocol_counts.get("ICMP", 0),
        "arp_count": protocol_counts.get("ARP", 0),
        "other_count": (
            protocol_counts.get("IP", 0) + protocol_counts.get("Other", 0)
        ),
    }


def detect_port_scanning(df, port_threshold=5):
    if df.empty:
        return []

    tcp_df = df[(df["protocol"] == "TCP") & (df["dst_port"].notna())].copy()

    if tcp_df.empty:
        return []

    grouped = (
        tcp_df.groupby(["src_ip", "dst_ip"])["dst_port"]
        .nunique()
        .reset_index(name="unique_dst_ports")
    )

    suspicious = grouped[grouped["unique_dst_ports"] >= port_threshold]

    results = []
    for _, row in suspicious.iterrows():
        results.append(
            {
                "alert_type": "Possible Port Scanning",
                "severity": "Medium",
                "src_ip": row["src_ip"],
                "dst_ip": row["dst_ip"],
                "unique_dst_ports": int(row["unique_dst_ports"]),
            }
        )

    return results


def detect_arp_spoofing(arp_records):
    if not arp_records:
        return []

    ip_to_macs = defaultdict(set)

    for entry in arp_records:
        ip_to_macs[entry["ip"]].add(entry["mac"])

    results = []
    for ip, macs in ip_to_macs.items():
        if len(macs) > 1:
            results.append(
                {
                    "alert_type": "Possible ARP Spoofing",
                    "severity": "High",
                    "ip": ip,
                    "mac_addresses": ", ".join(sorted(macs)),
                    "unique_macs": len(macs),
                }
            )

    return results


def detect_ddos(df, source_threshold=20, packet_threshold=50):
    if df.empty:
        return []

    tcp_df = df[
        (df["protocol"] == "TCP")
        & (df["src_ip"] != "N/A")
        & (df["dst_ip"] != "N/A")
        & (df["tcp_flags"].notna())
    ].copy()

    if tcp_df.empty:
        return []

    syn_df = tcp_df[tcp_df["tcp_flags"].astype(str).str.contains("S")].copy()

    if syn_df.empty:
        return []

    grouped = (
        syn_df.groupby("dst_ip")
        .agg(
            unique_source_ips=("src_ip", "nunique"),
            total_syn_packets=("src_ip", "count"),
        )
        .reset_index()
    )

    suspicious = grouped[
        (grouped["unique_source_ips"] >= source_threshold)
        & (grouped["total_syn_packets"] >= packet_threshold)
    ]

    results = []
    for _, row in suspicious.iterrows():
        results.append(
            {
                "alert_type": "Possible DDoS / SYN Flood",
                "severity": "High",
                "dst_ip": row["dst_ip"],
                "unique_source_ips": int(row["unique_source_ips"]),
                "total_syn_packets": int(row["total_syn_packets"]),
            }
        )

    return results


def detect_beaconing(df, min_connections=4, interval_tolerance=2.0):
    if df.empty or "timestamp" not in df.columns:
        return []

    flow_df = df[
        (df["src_ip"] != "N/A")
        & (df["dst_ip"] != "N/A")
        & (df["protocol"].isin(["TCP", "UDP"]))
    ].copy()

    if flow_df.empty:
        return []

    connection_times = defaultdict(list)

    for _, row in flow_df.iterrows():
        key = (row["src_ip"], row["dst_ip"], row["dst_port"], row["protocol"])
        if row["timestamp"] is not None:
            connection_times[key].append(float(row["timestamp"]))

    results = []

    for (src_ip, dst_ip, dst_port, protocol), times in connection_times.items():
        if len(times) < min_connections:
            continue

        times = sorted(times)
        intervals = [times[i + 1] - times[i] for i in range(len(times) - 1)]

        if len(intervals) < 3:
            continue

        avg_interval = sum(intervals) / len(intervals)
        deviation = pstdev(intervals) if len(intervals) > 1 else 0

        if deviation <= interval_tolerance:
            results.append(
                {
                    "alert_type": "Possible Beaconing",
                    "severity": "Medium",
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "dst_port": dst_port,
                    "protocol": protocol,
                    "connection_count": len(times),
                    "avg_interval_sec": round(avg_interval, 2),
                    "interval_stddev": round(deviation, 2),
                }
            )

    return results


def detect_unusual_outbound_connections(
    df,
    external_host_threshold=3,
    packet_threshold=5,
    unusual_ports=None,
):
    if df.empty:
        return []

    if unusual_ports is None:
        unusual_ports = {
            4444, 5555, 6666, 7777, 8081, 1337, 31337, 12345, 54321, 9001
        }

    valid_df = df[(df["src_ip"] != "N/A") & (df["dst_ip"] != "N/A")].copy()

    if valid_df.empty:
        return []

    external_contacts_by_src = defaultdict(set)
    flow_stats = defaultdict(
        lambda: {
            "count": 0,
            "bytes": 0,
            "protocols": set(),
            "dst_ports": set(),
        }
    )

    for _, row in valid_df.iterrows():
        src = row["src_ip"]
        dst = row["dst_ip"]
        proto = row["protocol"]

        if is_internal_ip(src) and not is_internal_ip(dst):
            key = (src, dst)
            external_contacts_by_src[src].add(dst)
            flow_stats[key]["count"] += 1
            flow_stats[key]["bytes"] += int(row["length"])
            flow_stats[key]["protocols"].add(proto)

            if pd.notna(row["dst_port"]):
                flow_stats[key]["dst_ports"].add(int(row["dst_port"]))

    results = []

    for (src, dst), stats in flow_stats.items():
        reasons = []

        unusual_dst_ports = sorted(
            [port for port in stats["dst_ports"] if port in unusual_ports]
        )

        if unusual_dst_ports:
            reasons.append(f"Unusual destination ports: {unusual_dst_ports}")

        if len(external_contacts_by_src[src]) >= external_host_threshold:
            reasons.append(
                f"Contacted many external IPs: {len(external_contacts_by_src[src])}"
            )

        if stats["count"] >= packet_threshold and "ICMP" in stats["protocols"]:
            reasons.append(f"High-volume outbound ICMP: {stats['count']} packets")

        if reasons:
            results.append(
                {
                    "alert_type": "Possible Unusual Outbound Connection",
                    "severity": "Medium",
                    "src_ip": src,
                    "dst_ip": dst,
                    "packet_count": stats["count"],
                    "total_bytes": stats["bytes"],
                    "protocols": ", ".join(sorted(stats["protocols"])),
                    "dst_ports": ", ".join(map(str, sorted(stats["dst_ports"]))),
                    "reason": " | ".join(reasons),
                }
            )

    return results


def detect_data_exfiltration(df, byte_threshold=20000):
    if df.empty:
        return []

    valid_df = df[(df["src_ip"] != "N/A") & (df["dst_ip"] != "N/A")].copy()

    if valid_df.empty:
        return []

    outbound = valid_df[
        valid_df.apply(
            lambda row: is_internal_ip(row["src_ip"]) and not is_internal_ip(row["dst_ip"]),
            axis=1,
        )
    ].copy()

    if outbound.empty:
        return []

    grouped = (
        outbound.groupby(["src_ip", "dst_ip"])["length"]
        .sum()
        .reset_index(name="total_bytes_sent")
    )

    suspicious = grouped[grouped["total_bytes_sent"] >= byte_threshold]

    results = []
    for _, row in suspicious.iterrows():
        results.append(
            {
                "alert_type": "Possible Data Exfiltration",
                "severity": "High",
                "src_ip": row["src_ip"],
                "dst_ip": row["dst_ip"],
                "total_bytes_sent": int(row["total_bytes_sent"]),
            }
        )

    return results


def detect_icmp_flood(df, icmp_threshold=3):
    if df.empty:
        return []

    icmp_df = df[df["protocol"] == "ICMP"].copy()

    if icmp_df.empty:
        return []

    grouped = (
        icmp_df.groupby(["src_ip", "dst_ip"])
        .size()
        .reset_index(name="icmp_count")
    )

    suspicious = grouped[grouped["icmp_count"] >= icmp_threshold]

    results = []
    for _, row in suspicious.iterrows():
        results.append(
            {
                "alert_type": "Possible ICMP Flood",
                "severity": "Medium",
                "src_ip": row["src_ip"],
                "dst_ip": row["dst_ip"],
                "icmp_count": int(row["icmp_count"]),
            }
        )

    return results

def detect_icmp_sweep(df, target_threshold=5):
    if df.empty:
        return []

    icmp_df = df[
        (df["protocol"] == "ICMP")
        & (df["src_ip"] != "N/A")
        & (df["dst_ip"] != "N/A")
    ].copy()

    if icmp_df.empty:
        return []

    grouped = (
        icmp_df.groupby("src_ip")["dst_ip"]
        .nunique()
        .reset_index(name="unique_targets")
    )

    suspicious = grouped[grouped["unique_targets"] >= target_threshold]

    results = []
    for _, row in suspicious.iterrows():
        results.append(
            {
                "alert_type": "Possible ICMP Sweep",
                "severity": "Medium",
                "src_ip": row["src_ip"],
                "unique_targets": int(row["unique_targets"]),
            }
        )

    return results

def detect_large_packets(df, size_threshold=1000):
    if df.empty:
        return []

    suspicious = df[df["length"] >= size_threshold].copy()

    results = []
    for _, row in suspicious.iterrows():
        results.append(
            {
                "alert_type": "Large Packet",
                "severity": "Low",
                "src_ip": row["src_ip"],
                "dst_ip": row["dst_ip"],
                "length": int(row["length"]),
                "protocol": row["protocol"],
            }
        )

    return results