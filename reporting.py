import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


def utc_iso(ts: Optional[float]) -> str:
    if ts is None:
        return "N/A"
    try:
        return datetime.fromtimestamp(float(ts), tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return str(ts)


def build_report_json(
    *,
    run_id: str,
    run_meta: Dict[str, Any],
    input_meta: Dict[str, Any],
    config: Dict[str, Any],
    traffic_summary: Dict[str, Any],
    findings: List[Dict[str, Any]],
) -> Dict[str, Any]:
    return {
        "run": {"run_id": run_id, **run_meta},
        "input": input_meta,
        "config": config,
        "traffic_summary": traffic_summary,
        "findings": findings,
        "generated_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }


def build_report_html(
    *,
    run_id: str,
    report_json: Dict[str, Any],
    chart_paths: Optional[List[str]] = None,
) -> str:
    chart_paths = chart_paths or []
    findings = report_json.get("findings", []) or []

    def esc(s: Any) -> str:
        return (
            str(s)
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
        )

    # Simple, portable HTML (no external assets)
    rows = []
    for f in findings:
        rows.append(
            "<tr>"
            f"<td>{esc(f.get('severity', ''))}</td>"
            f"<td>{esc(f.get('alert_type', ''))}</td>"
            f"<td>{esc(f.get('src_ip', f.get('ip', '')))}</td>"
            f"<td>{esc(f.get('dst_ip', ''))}</td>"
            f"<td>{esc(f.get('protocol', ''))}</td>"
            f"<td>{esc(f.get('dst_port', ''))}</td>"
            f"<td>{esc(f.get('reason', ''))}</td>"
            f"<td>{esc(utc_iso(f.get('first_seen_ts') or f.get('first_seen')))}</td>"
            f"<td>{esc(utc_iso(f.get('last_seen_ts') or f.get('last_seen')))}</td>"
            "</tr>"
        )

    charts_html = ""
    if chart_paths:
        imgs = []
        for p in chart_paths:
            name = os.path.basename(p)
            imgs.append(f"<div class='chart'><div class='caption'>{esc(name)}</div><img src='artifacts/{esc(name)}'/></div>")
        charts_html = "<div class='charts'>" + "".join(imgs) + "</div>"

    pretty_json = json.dumps(report_json, indent=2, ensure_ascii=False)
    return f"""
<!doctype html>
<html>
<head>
  <meta charset="utf-8"/>
  <title>NetSleuth IR Report - {esc(run_id)}</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 20px; color: #111; }}
    h1 {{ margin: 0 0 6px 0; }}
    .meta {{ margin: 10px 0 18px 0; padding: 10px 12px; border: 1px solid #ddd; border-radius: 8px; }}
    .grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 10px 18px; }}
    .kv {{ font-size: 13px; }}
    .k {{ color: #444; font-weight: 700; }}
    table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
    th, td {{ border: 1px solid #ddd; padding: 6px 8px; font-size: 12px; vertical-align: top; }}
    th {{ background: #f6f6f6; text-align: left; }}
    .charts {{ display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin: 14px 0; }}
    .chart {{ border: 1px solid #ddd; border-radius: 8px; padding: 8px; }}
    .chart img {{ width: 100%; height: auto; }}
    .caption {{ font-size: 12px; color: #444; margin: 0 0 6px 0; }}
    pre {{ white-space: pre-wrap; border: 1px solid #eee; padding: 10px; border-radius: 8px; background: #fafafa; }}
  </style>
</head>
<body>
  <h1>NetSleuth IR Report</h1>
  <div class="meta">
    <div class="grid">
      <div class="kv"><span class="k">Run ID:</span> {esc(run_id)}</div>
      <div class="kv"><span class="k">Generated:</span> {esc(report_json.get("generated_at_utc", ""))}</div>
      <div class="kv"><span class="k">Source:</span> {esc(report_json.get("input", {}).get("source_type", ""))}</div>
      <div class="kv"><span class="k">PCAP SHA-256:</span> {esc(report_json.get("input", {}).get("sha256", ""))}</div>
    </div>
  </div>

  <h2>Traffic Summary</h2>
  <pre>{esc(json.dumps(report_json.get("traffic_summary", {}), indent=2, ensure_ascii=False))}</pre>

  <h2>Charts</h2>
  {charts_html if charts_html else "<p>No charts exported.</p>"}

  <h2>Findings</h2>
  <table>
    <thead>
      <tr>
        <th>Severity</th><th>Type</th><th>Src</th><th>Dst</th><th>Proto</th><th>Dst Port</th><th>Reason</th><th>First Seen</th><th>Last Seen</th>
      </tr>
    </thead>
    <tbody>
      {''.join(rows) if rows else '<tr><td colspan="9">No findings.</td></tr>'}
    </tbody>
  </table>

  <h2>Full JSON</h2>
  <pre>{esc(pretty_json)}</pre>
</body>
</html>
""".strip()

