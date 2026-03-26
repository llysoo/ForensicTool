# WireWatch

WireWatch is a Python-based network forensics and incident response tool built for a Digital Forensics class project. It helps investigators capture or import packet data, analyze suspicious traffic patterns, detect common network threats, and preserve findings as case evidence.

The project focuses on practical incident response workflows instead of raw packet viewing alone. In addition to packet parsing and anomaly detection, it supports evidence storage, case artifacts, and exportable reports.

## Course Context

This project was developed for a Network Forensics topic under Incident Response and Network Anomaly Detection.

Target requirement:

- Capture and analyze PCAP files or live network traffic
- Detect unusual outbound connections, beaconing, and possible data leaks
- Identify signs of port scanning, ARP spoofing, and DDoS attacks
- Provide a visualized report of findings

## Core Features

- Import and analyze `.pcap` files
- Capture live traffic from a selected network interface
- Apply capture filters for protocol, host, port, and custom BPF expressions
- Parse packet metadata such as timestamps, IPs, ports, transport protocol, and selected application-layer details
- Reconstruct TCP and UDP sessions into conversations
- Generate traffic summaries including protocol counts, top source IPs, top destination IPs, DNS queries, and HTTP hosts
- Detect suspicious behaviors such as:
  - Port scanning
  - Rate-based port scanning
  - ARP spoofing
  - DDoS / SYN flood behavior
  - Rate-based SYN flood behavior
  - Beaconing / periodic communication
  - Unusual outbound connections
  - Rare outbound destinations
  - Possible data exfiltration
  - DNS anomalies and possible DNS tunneling
  - ICMP flood and ICMP sweep behavior
  - Unusually large packets
- Visualize findings with charts, timelines, and a network graph
- Export findings and evidence as CSV, HTML, JSON, SQLite case data, and ZIP case bundles

## Project Structure

- `app.py`
  Streamlit dashboard, live capture workflow, packet exploration, chart rendering, report export, and evidence bundle generation.

- `detectors.py`
  Packet parsing, session reconstruction, traffic summaries, and detection heuristics for suspicious network activity.

- `evidence_store.py`
  SQLite-backed evidence store for run metadata, inputs, detector configuration snapshots, alerts, packet references, and artifact records.

- `reporting.py`
  Portable JSON and HTML report generation for investigation output.

- `cases/`
  Generated case folders containing stored PCAPs, report artifacts, charts, and the evidence database.

## Technologies Used

- Python
- Streamlit
- Scapy
- pandas
- matplotlib
- networkx
- SQLite

## Installation

1. Install Python 3.10+.
2. Clone or download the project folder.
3. Install dependencies:

```bash
pip install -r requirements.txt
```

4. Run the dashboard:

```bash
streamlit run app.py
```

## Typical Workflow

### PCAP Analysis

1. Launch the Streamlit app.
2. Choose `Upload PCAP`.
3. Upload a packet capture file.
4. Review traffic summary, session reconstruction, and detection results.
5. Use search and filtering tools to inspect suspicious traffic.
6. Export findings as CSV or generate a case bundle for documentation.

### Live Capture

1. Launch the Streamlit app with sufficient privileges for packet capture.
2. Choose `Live Capture`.
3. Select a network interface and optional filters.
4. Start capture and wait for the collection window to finish.
5. Review detections, alerts, charts, and exported evidence.

## Supported Detections

- `Port Scanning`
  Flags a source IP that targets many destination ports on the same destination host.

- `Rate-Based Port Scanning`
  Flags rapid multi-port targeting inside a short time window.

- `ARP Spoofing`
  Flags multiple MAC addresses claiming the same IP address.

- `DDoS / SYN Flood`
  Flags many SYN requests from multiple sources to one destination.

- `Rate-Based SYN Flood`
  Flags high SYN-per-second spikes against one destination in a short window.

- `Beaconing`
  Flags periodic communication patterns that may indicate command-and-control behavior.

- `Unusual Outbound Connections`
  Flags suspicious outbound traffic patterns such as unusual ports, many external destinations, or high-volume outbound ICMP.

- `Rare Outbound Destinations`
  Flags less-common external destinations for a given internal source host.

- `Possible Data Exfiltration`
  Flags unusually large outbound data transfers to external destinations.

- `DNS Anomaly / Possible DNS Tunneling`
  Flags high-volume DNS behavior, high NXDOMAIN ratios, and suspiciously long or high-entropy DNS labels.

- `ICMP Flood / ICMP Sweep`
  Flags possible flood behavior and host-discovery style sweeps.

- `Large Packet Detection`
  Flags unusually large packets for additional review.

## Visualization and Reporting

The tool includes several built-in investigation views:

- Traffic summary tables
- Protocol distribution chart
- Findings overview charts
- Alert timeline chart
- Network graph of top flows
- Parsed packet table
- Filtered packet search results
- Payload inspection view

Export outputs include:

- Findings CSV
- `report.json`
- `report.html`
- SQLite case database
- Chart images
- ZIP case bundle containing evidence artifacts

## Logging and Evidence Collection

WireWatch supports a lightweight forensic workflow by preserving:

- Run metadata
- Analyst name and notes
- Input source details
- SHA-256 hashes for saved packet captures and artifacts
- Detector configuration snapshot
- Alerts and evidence packet references
- Exported reports and chart artifacts

This helps document how a finding was produced and what evidence was saved during analysis.

## Requirement Mapping

### 1. Capture and analyze PCAP files or live network traffic

Met through:

- PCAP upload and parsing
- Live packet capture
- Packet metadata extraction
- Session reconstruction

### 2. Detect unusual outbound connections, C2, and data leaks

Met through:

- Unusual outbound connection detection
- Beaconing detection
- Rare outbound destination detection
- Data exfiltration heuristics
- DNS anomaly heuristics

### 3. Identify port scanning, ARP spoofing, and DDoS attacks

Met through:

- Port scanning detection
- Rate-based port scanning detection
- ARP spoofing detection
- DDoS / SYN flood detection
- Rate-based SYN flood detection

### 4. Provide a visualized report of findings

Met through:

- Findings charts
- Alert timeline visualization
- Network graph
- Downloadable HTML, JSON, CSV, and ZIP outputs

## Known Limitations

- Detection is heuristic-based and should support analyst review, not replace it.
- Thresholds are static and may need tuning for different network environments.
- The tool does not perform full TCP stream reassembly like Wireshark.
- PDF export is not currently implemented.
- Encrypted traffic cannot be deeply inspected without decryption context.
- Large captures may affect dashboard responsiveness.

## Future Improvements

- Add automated tests for detector logic
- Add PDF export for formal reporting
- Improve stream-following and conversation reconstruction
- Add more configurable detector thresholds from the UI
- Expand protocol parsing and artifact extraction
- Improve baseline-aware anomaly detection for enterprise traffic
