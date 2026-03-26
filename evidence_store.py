import base64
import hashlib
import json
import os
import sqlite3
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def sha256_bytes(data: bytes) -> str:
    h = hashlib.sha256()
    h.update(data)
    return h.hexdigest()


def safe_filename(name: str) -> str:
    keep = []
    for ch in (name or "").strip():
        if ch.isalnum() or ch in ("-", "_", ".", " "):
            keep.append(ch)
        else:
            keep.append("_")
    out = "".join(keep).strip().replace("  ", " ")
    return out[:180] if out else "case"


def ensure_dir(path: str) -> str:
    os.makedirs(path, exist_ok=True)
    return path


@dataclass(frozen=True)
class EvidencePaths:
    case_dir: str
    db_path: str
    artifacts_dir: str


def create_case_paths(base_dir: str, case_name: str, run_id: str) -> EvidencePaths:
    base_dir = os.path.abspath(base_dir)
    case_slug = safe_filename(case_name)
    case_dir = ensure_dir(os.path.join(base_dir, f"{case_slug}_{run_id}"))
    artifacts_dir = ensure_dir(os.path.join(case_dir, "artifacts"))
    db_path = os.path.join(case_dir, "case.db")
    return EvidencePaths(case_dir=case_dir, db_path=db_path, artifacts_dir=artifacts_dir)


class EvidenceStore:
    """
    A lightweight IR evidence store (SQLite) for:
    - run metadata
    - input provenance + hashes
    - config snapshot
    - alerts + evidence pointers (packet/session references)
    - artifacts (report files, charts, pcap copy)
    """

    def __init__(self, db_path: str):
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path)
        self.conn.row_factory = sqlite3.Row
        self._init_schema()

    def close(self) -> None:
        try:
            self.conn.close()
        except Exception:
            pass

    def _init_schema(self) -> None:
        cur = self.conn.cursor()
        cur.executescript(
            """
            PRAGMA journal_mode=WAL;
            PRAGMA foreign_keys=ON;

            CREATE TABLE IF NOT EXISTS runs (
              run_id TEXT PRIMARY KEY,
              created_at_utc TEXT NOT NULL,
              tool_name TEXT,
              tool_version TEXT,
              analyst TEXT,
              notes TEXT,
              mode TEXT
            );

            CREATE TABLE IF NOT EXISTS inputs (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              run_id TEXT NOT NULL,
              source_type TEXT NOT NULL,     -- upload|live
              original_name TEXT,
              size_bytes INTEGER,
              sha256 TEXT,
              capture_interface TEXT,
              capture_filter TEXT,
              capture_seconds INTEGER,
              packet_count INTEGER,
              first_packet_ts REAL,
              last_packet_ts REAL,
              saved_pcap_path TEXT,
              FOREIGN KEY(run_id) REFERENCES runs(run_id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS config (
              run_id TEXT NOT NULL,
              key TEXT NOT NULL,
              value_json TEXT NOT NULL,
              PRIMARY KEY(run_id, key),
              FOREIGN KEY(run_id) REFERENCES runs(run_id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS alerts (
              alert_id TEXT PRIMARY KEY,
              run_id TEXT NOT NULL,
              alert_type TEXT NOT NULL,
              severity TEXT,
              status TEXT,
              src_ip TEXT,
              dst_ip TEXT,
              src_port INTEGER,
              dst_port INTEGER,
              protocol TEXT,
              reason TEXT,
              first_seen_ts REAL,
              last_seen_ts REAL,
              details_json TEXT,
              created_at_utc TEXT NOT NULL,
              FOREIGN KEY(run_id) REFERENCES runs(run_id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS alert_packets (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              alert_id TEXT NOT NULL,
              packet_no INTEGER NOT NULL,
              FOREIGN KEY(alert_id) REFERENCES alerts(alert_id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS alert_sessions (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              alert_id TEXT NOT NULL,
              session_id TEXT NOT NULL,
              FOREIGN KEY(alert_id) REFERENCES alerts(alert_id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS artifacts (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              run_id TEXT NOT NULL,
              kind TEXT NOT NULL,       -- report_html|report_json|chart_png|pcap|zip|other
              path TEXT NOT NULL,
              sha256 TEXT,
              created_at_utc TEXT NOT NULL,
              FOREIGN KEY(run_id) REFERENCES runs(run_id) ON DELETE CASCADE
            );
            """
        )
        self.conn.commit()

    def create_run(
        self,
        run_id: str,
        tool_name: str = "WireWatch",
        tool_version: Optional[str] = None,
        analyst: Optional[str] = None,
        notes: Optional[str] = None,
        mode: Optional[str] = None,
    ) -> None:
        self.conn.execute(
            """
            INSERT OR REPLACE INTO runs(run_id, created_at_utc, tool_name, tool_version, analyst, notes, mode)
            VALUES(?, ?, ?, ?, ?, ?, ?)
            """,
            (run_id, utc_now_iso(), tool_name, tool_version, analyst, notes, mode),
        )
        self.conn.commit()

    def add_input(self, run_id: str, **fields: Any) -> None:
        cols = [
            "run_id",
            "source_type",
            "original_name",
            "size_bytes",
            "sha256",
            "capture_interface",
            "capture_filter",
            "capture_seconds",
            "packet_count",
            "first_packet_ts",
            "last_packet_ts",
            "saved_pcap_path",
        ]
        values = [run_id] + [fields.get(c) for c in cols[1:]]
        self.conn.execute(
            f"INSERT INTO inputs({', '.join(cols)}) VALUES({', '.join(['?'] * len(cols))})",
            values,
        )
        self.conn.commit()

    def set_config(self, run_id: str, key: str, value: Any) -> None:
        self.conn.execute(
            "INSERT OR REPLACE INTO config(run_id, key, value_json) VALUES(?, ?, ?)",
            (run_id, key, json.dumps(value, ensure_ascii=False)),
        )
        self.conn.commit()

    def add_artifact(self, run_id: str, kind: str, path: str, sha256: Optional[str] = None) -> None:
        self.conn.execute(
            "INSERT INTO artifacts(run_id, kind, path, sha256, created_at_utc) VALUES(?, ?, ?, ?, ?)",
            (run_id, kind, path, sha256, utc_now_iso()),
        )
        self.conn.commit()

    def _stable_alert_id(self, run_id: str, core: Dict[str, Any]) -> str:
        payload = json.dumps({"run_id": run_id, **core}, sort_keys=True, ensure_ascii=False)
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]

    def add_alert(
        self,
        run_id: str,
        alert: Dict[str, Any],
        packet_nos: Optional[Iterable[int]] = None,
        session_ids: Optional[Iterable[str]] = None,
    ) -> str:
        core = {
            "alert_type": alert.get("alert_type"),
            "src_ip": alert.get("src_ip", alert.get("ip")),
            "dst_ip": alert.get("dst_ip"),
            "src_port": alert.get("src_port"),
            "dst_port": alert.get("dst_port"),
            "protocol": alert.get("protocol"),
            "first_seen_ts": alert.get("first_seen_ts", alert.get("first_seen")),
            "last_seen_ts": alert.get("last_seen_ts", alert.get("last_seen")),
            "reason": alert.get("reason"),
        }
        alert_id = str(alert.get("alert_id") or self._stable_alert_id(run_id, core))

        details = dict(alert)
        # Remove redundant / top-level fields from details for readability
        for k in (
            "alert_id",
            "alert_type",
            "severity",
            "status",
            "src_ip",
            "dst_ip",
            "src_port",
            "dst_port",
            "protocol",
            "reason",
            "first_seen_ts",
            "last_seen_ts",
        ):
            details.pop(k, None)

        self.conn.execute(
            """
            INSERT OR REPLACE INTO alerts(
              alert_id, run_id, alert_type, severity, status,
              src_ip, dst_ip, src_port, dst_port, protocol,
              reason, first_seen_ts, last_seen_ts, details_json, created_at_utc
            )
            VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                alert_id,
                run_id,
                str(alert.get("alert_type", "Unknown")),
                alert.get("severity"),
                alert.get("status"),
                alert.get("src_ip", alert.get("ip")),
                alert.get("dst_ip"),
                int(alert["src_port"]) if alert.get("src_port") is not None else None,
                int(alert["dst_port"]) if alert.get("dst_port") is not None else None,
                alert.get("protocol"),
                alert.get("reason"),
                float(alert["first_seen_ts"]) if alert.get("first_seen_ts") is not None else (
                    float(alert["first_seen"]) if alert.get("first_seen") is not None else None
                ),
                float(alert["last_seen_ts"]) if alert.get("last_seen_ts") is not None else (
                    float(alert["last_seen"]) if alert.get("last_seen") is not None else None
                ),
                json.dumps(details, ensure_ascii=False),
                utc_now_iso(),
            ),
        )

        if packet_nos:
            self.conn.executemany(
                "INSERT INTO alert_packets(alert_id, packet_no) VALUES(?, ?)",
                [(alert_id, int(p)) for p in packet_nos],
            )
        if session_ids:
            self.conn.executemany(
                "INSERT INTO alert_sessions(alert_id, session_id) VALUES(?, ?)",
                [(alert_id, str(s)) for s in session_ids],
            )
        self.conn.commit()
        return alert_id


def write_bytes_artifact(path: str, data: bytes) -> str:
    ensure_dir(os.path.dirname(os.path.abspath(path)))
    with open(path, "wb") as f:
        f.write(data)
    return sha256_bytes(data)


def write_text_artifact(path: str, text: str) -> str:
    b = text.encode("utf-8")
    ensure_dir(os.path.dirname(os.path.abspath(path)))
    with open(path, "wb") as f:
        f.write(b)
    return sha256_bytes(b)


def to_data_uri_png(png_bytes: bytes) -> str:
    return "data:image/png;base64," + base64.b64encode(png_bytes).decode("ascii")

