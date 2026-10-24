from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable

from .crypto import SecureBox, sha256_hex

SCHEMA = """
CREATE TABLE IF NOT EXISTS flows (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    method TEXT NOT NULL DEFAULT '',
    scheme TEXT NOT NULL DEFAULT '',
    host TEXT NOT NULL DEFAULT '',
    port INTEGER NOT NULL DEFAULT 0,
    path TEXT NOT NULL DEFAULT '',
    status INTEGER NOT NULL DEFAULT 0,
    req_bytes INTEGER NOT NULL DEFAULT 0,
    resp_bytes INTEGER NOT NULL DEFAULT 0,
    duration_ms INTEGER NOT NULL DEFAULT 0,
    content_type TEXT NOT NULL DEFAULT '',
    pid INTEGER,
    proc_name TEXT NOT NULL DEFAULT '',
    proc_path TEXT NOT NULL DEFAULT '',
    ppid INTEGER,
    proc_user TEXT NOT NULL DEFAULT '',
    proc_create_time REAL,
    cmdline TEXT NOT NULL DEFAULT '',
    app_chain TEXT NOT NULL DEFAULT '[]',
    app_kind TEXT NOT NULL DEFAULT '',
    category TEXT NOT NULL DEFAULT 'other',
    provider TEXT NOT NULL DEFAULT '',
    endpoint_kind TEXT NOT NULL DEFAULT '',
    model TEXT NOT NULL DEFAULT '',
    risk INTEGER NOT NULL DEFAULT 0,
    severity TEXT NOT NULL DEFAULT 'info',
    action TEXT NOT NULL DEFAULT 'observe',
    blocked INTEGER NOT NULL DEFAULT 0,
    req_preview TEXT NOT NULL DEFAULT '',
    resp_preview TEXT NOT NULL DEFAULT '',
    req_sha TEXT NOT NULL DEFAULT '',
    resp_sha TEXT NOT NULL DEFAULT '',
    enc_req BLOB,
    enc_resp BLOB,
    client_ip TEXT NOT NULL DEFAULT '',
    client_port INTEGER,
    tls TEXT NOT NULL DEFAULT '',
    tags TEXT NOT NULL DEFAULT '[]',
    headers_json TEXT NOT NULL DEFAULT '{}',
    note TEXT NOT NULL DEFAULT '',
    coverage TEXT NOT NULL DEFAULT 'proxied'
);
CREATE INDEX IF NOT EXISTS idx_flows_ts ON flows(ts DESC);
CREATE INDEX IF NOT EXISTS idx_flows_pid ON flows(pid, ts DESC);
CREATE INDEX IF NOT EXISTS idx_flows_host ON flows(host);
CREATE INDEX IF NOT EXISTS idx_flows_risk ON flows(risk DESC, ts DESC);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    flow_id INTEGER NOT NULL REFERENCES flows(id) ON DELETE CASCADE,
    ts REAL NOT NULL,
    rule_id TEXT NOT NULL,
    title TEXT NOT NULL,
    category TEXT NOT NULL DEFAULT '',
    severity TEXT NOT NULL DEFAULT 'info',
    score INTEGER NOT NULL DEFAULT 0,
    direction TEXT NOT NULL DEFAULT 'request',
    detail TEXT NOT NULL DEFAULT '',
    evidence TEXT NOT NULL DEFAULT '',
    action TEXT NOT NULL DEFAULT 'observe'
);
CREATE INDEX IF NOT EXISTS idx_findings_flow ON findings(flow_id);
CREATE INDEX IF NOT EXISTS idx_findings_ts ON findings(ts DESC);

CREATE TABLE IF NOT EXISTS file_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    pid INTEGER,
    proc_name TEXT NOT NULL DEFAULT '',
    proc_path TEXT NOT NULL DEFAULT '',
    path TEXT NOT NULL DEFAULT '',
    action TEXT NOT NULL DEFAULT 'open',
    sensitivity TEXT NOT NULL DEFAULT 'low',
    canary INTEGER NOT NULL DEFAULT 0,
    flow_id INTEGER
);
CREATE INDEX IF NOT EXISTS idx_file_events_ts ON file_events(ts DESC);
CREATE INDEX IF NOT EXISTS idx_file_events_pid ON file_events(pid, ts DESC);

CREATE TABLE IF NOT EXISTS canaries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    name TEXT NOT NULL DEFAULT '',
    path TEXT NOT NULL UNIQUE,
    triggered_at REAL,
    triggered_pid INTEGER
);

CREATE TABLE IF NOT EXISTS audit_chain (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    flow_id INTEGER NOT NULL,
    ts REAL NOT NULL,
    prev_hash TEXT NOT NULL,
    hash TEXT NOT NULL,
    summary TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""


class Store:
    def __init__(self, db_path: Path, box: SecureBox) -> None:
        self.db_path = db_path
        self.box = box
        self._lock = threading.RLock()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(db_path), check_same_thread=False, timeout=10)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._conn.executescript(SCHEMA)
        self._conn.execute("INSERT OR IGNORE INTO meta(key, value) VALUES('schema_version', '1')")
        self._conn.commit()
        self._last_hash = self._load_last_hash()

    def close(self) -> None:
        with self._lock:
            try:
                self._conn.commit()
                self._conn.close()
            except sqlite3.Error:
                pass

    def _load_last_hash(self) -> str:
        row = self._conn.execute("SELECT hash FROM audit_chain ORDER BY id DESC LIMIT 1").fetchone()
        return row["hash"] if row else "GENESIS"

    def insert_flow(self, record: dict[str, Any], findings: list[dict[str, Any]]) -> int:
        ts = float(record.get("ts") or time.time())
        columns = {
            "ts": ts,
            "method": record.get("method", ""),
            "scheme": record.get("scheme", ""),
            "host": record.get("host", ""),
            "port": int(record.get("port") or 0),
            "path": record.get("path", ""),
            "status": int(record.get("status") or 0),
            "req_bytes": int(record.get("req_bytes") or 0),
            "resp_bytes": int(record.get("resp_bytes") or 0),
            "duration_ms": int(record.get("duration_ms") or 0),
            "content_type": record.get("content_type", ""),
            "pid": record.get("pid"),
            "proc_name": record.get("proc_name", ""),
            "proc_path": record.get("proc_path", ""),
            "ppid": record.get("ppid"),
            "proc_user": record.get("proc_user", ""),
            "proc_create_time": record.get("proc_create_time"),
            "cmdline": record.get("cmdline", ""),
            "app_chain": json.dumps(record.get("app_chain") or [], ensure_ascii=False),
            "app_kind": record.get("app_kind", ""),
            "category": record.get("category", "other"),
            "provider": record.get("provider", ""),
            "endpoint_kind": record.get("endpoint_kind", ""),
            "model": record.get("model", ""),
            "risk": int(record.get("risk") or 0),
            "severity": record.get("severity", "info"),
            "action": record.get("action", "observe"),
            "blocked": 1 if record.get("blocked") else 0,
            "req_preview": record.get("req_preview", ""),
            "resp_preview": record.get("resp_preview", ""),
            "req_sha": record.get("req_sha", ""),
            "resp_sha": record.get("resp_sha", ""),
            "enc_req": record.get("enc_req"),
            "enc_resp": record.get("enc_resp"),
            "client_ip": record.get("client_ip", ""),
            "client_port": record.get("client_port"),
            "tls": record.get("tls", ""),
            "tags": json.dumps(record.get("tags") or [], ensure_ascii=False),
            "headers_json": record.get("headers_json", "{}"),
            "note": record.get("note", ""),
            "coverage": record.get("coverage", "proxied"),
        }
        with self._lock, self._conn:
            placeholders = ", ".join("?" for _ in columns)
            cur = self._conn.execute(
                f"INSERT INTO flows ({', '.join(columns)}) VALUES ({placeholders})",
                list(columns.values()),
            )
            flow_id = int(cur.lastrowid)
            for finding in findings:
                self._conn.execute(
                    """INSERT INTO findings
                    (flow_id, ts, rule_id, title, category, severity, score, direction, detail, evidence, action)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        flow_id,
                        ts,
                        finding.get("rule_id", ""),
                        finding.get("title", ""),
                        finding.get("category", ""),
                        finding.get("severity", "info"),
                        int(finding.get("score") or 0),
                        finding.get("direction", "request"),
                        finding.get("detail", ""),
                        finding.get("evidence", ""),
                        finding.get("action", "observe"),
                    ),
                )
            summary = {
                "flow_id": flow_id,
                "ts": round(ts, 3),
                "method": columns["method"],
                "host": columns["host"],
                "path": columns["path"][:300],
                "status": columns["status"],
                "pid": columns["pid"],
                "risk": columns["risk"],
                "severity": columns["severity"],
                "action": columns["action"],
                "req_sha": columns["req_sha"],
                "resp_sha": columns["resp_sha"],
                "findings": sorted({f.get("rule_id", "") for f in findings}),
            }
            summary_json = json.dumps(summary, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
            prev_hash = self._last_hash
            digest = hashlib.sha256((prev_hash + summary_json).encode("utf-8")).hexdigest()
            self._conn.execute(
                "INSERT INTO audit_chain(flow_id, ts, prev_hash, hash, summary) VALUES (?, ?, ?, ?, ?)",
                (flow_id, ts, prev_hash, digest, summary_json),
            )
            self._last_hash = digest
        return flow_id

    def add_file_event(
        self,
        pid: int | None,
        proc_name: str,
        proc_path: str,
        path: str,
        action: str,
        sensitivity: str,
        canary: bool,
        ts: float | None = None,
    ) -> int | None:
        ts = ts or time.time()
        with self._lock, self._conn:
            if pid is not None:
                dup = self._conn.execute(
                    "SELECT id FROM file_events WHERE pid=? AND path=? AND ts>? LIMIT 1",
                    (pid, path, ts - 120),
                ).fetchone()
                if dup:
                    return None
            cur = self._conn.execute(
                """INSERT INTO file_events(ts, pid, proc_name, proc_path, path, action, sensitivity, canary)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (ts, pid, proc_name, proc_path, path, action, sensitivity, 1 if canary else 0),
            )
            if canary:
                self._conn.execute(
                    "UPDATE canaries SET triggered_at=?, triggered_pid=? WHERE path=?",
                    (ts, pid, path),
                )
            return int(cur.lastrowid)

    def add_canary(self, name: str, path: str) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT OR REPLACE INTO canaries(ts, name, path, triggered_at, triggered_pid) VALUES (?, ?, ?, NULL, NULL)",
                (time.time(), name, path),
            )

    def remove_canary_rows(self) -> None:
        with self._lock, self._conn:
            self._conn.execute("DELETE FROM canaries")

    def list_canaries(self) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute("SELECT * FROM canaries ORDER BY id").fetchall()
            return [dict(row) for row in rows]

    def list_flows(
        self,
        limit: int = 100,
        offset: int = 0,
        q: str = "",
        severity: str = "",
        category: str = "",
        ai_only: bool = False,
        since: float | None = None,
        pid: int | None = None,
        min_risk: int | None = None,
        blocked_only: bool = False,
    ) -> tuple[list[dict[str, Any]], int]:
        where: list[str] = []
        args: list[Any] = []
        if since:
            where.append("f.ts >= ?")
            args.append(float(since))
        if severity:
            values = [v for v in severity.split(",") if v in {"info", "low", "medium", "high", "critical"}]
            if values:
                where.append(f"f.severity IN ({', '.join('?' for _ in values)})")
                args.extend(values)
        if category:
            where.append("f.category = ?")
            args.append(category)
        if ai_only:
            where.append("f.category IN ('ai_service','ai_local','ai_candidate')")
        if pid is not None:
            where.append("f.pid = ?")
            args.append(pid)
        if min_risk is not None:
            where.append("f.risk >= ?")
            args.append(int(min_risk))
        if blocked_only:
            where.append("f.blocked = 1")
        if q:
            like = f"%{q}%"
            where.append(
                "(f.host LIKE ? OR f.path LIKE ? OR f.proc_name LIKE ? OR f.model LIKE ? OR f.req_preview LIKE ?)"
            )
            args.extend([like] * 5)
        clause = (" WHERE " + " AND ".join(where)) if where else ""
        with self._lock:
            total = self._conn.execute(f"SELECT COUNT(*) AS n FROM flows f{clause}", args).fetchone()["n"]
            rows = self._conn.execute(
                f"""SELECT f.id, f.ts, f.method, f.scheme, f.host, f.port, f.path, f.status,
                f.req_bytes, f.resp_bytes, f.duration_ms, f.pid, f.proc_name, f.proc_path,
                f.cmdline, f.app_chain, f.app_kind, f.category, f.provider, f.endpoint_kind, f.model, f.risk, f.severity,
                f.action, f.blocked, f.req_preview, f.resp_preview, f.tags, f.tls, f.coverage,
                f.client_ip, f.note,
                (SELECT COUNT(*) FROM findings x WHERE x.flow_id=f.id) AS finding_count
                FROM flows f{clause} ORDER BY f.ts DESC, f.id DESC LIMIT ? OFFSET ?""",
                [*args, max(1, min(500, limit)), max(0, offset)],
            ).fetchall()
        return [self._decode_row(dict(row)) for row in rows], int(total)

    def flow_detail(self, flow_id: int, reveal: bool = False) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute("SELECT * FROM flows WHERE id=?", (flow_id,)).fetchone()
            if not row:
                return None
            flow = self._decode_row(dict(row))
            findings = [
                dict(r)
                for r in self._conn.execute(
                    "SELECT * FROM findings WHERE flow_id=? ORDER BY score DESC, id", (flow_id,)
                ).fetchall()
            ]
            related: list[dict[str, Any]] = []
            if row["pid"] is not None:
                related = [
                    dict(r)
                    for r in self._conn.execute(
                        """SELECT * FROM file_events WHERE pid=? AND ts BETWEEN ? AND ?
                        ORDER BY ABS(ts - ?) LIMIT 12""",
                        (row["pid"], row["ts"] - 300, row["ts"] + 300, row["ts"]),
                    ).fetchall()
                ]
        enc_req = row["enc_req"]
        enc_resp = row["enc_resp"]
        flow["body_available"] = {"request": bool(enc_req), "response": bool(enc_resp)}
        for key, payload, aad in (("request_body", enc_req, b"req"), ("response_body", enc_resp, b"resp")):
            flow[key] = None
            flow[key + "_error"] = ""
            if payload and reveal:
                try:
                    raw = self.box.decrypt(payload, aad)
                    flow[key] = raw.decode("utf-8", "replace") if raw is not None else None
                except Exception as exc:  # key rotation / corrupted database
                    flow[key + "_error"] = type(exc).__name__
        flow.pop("enc_req", None)
        flow.pop("enc_resp", None)
        flow["findings"] = findings
        flow["related_files"] = related
        return flow

    def recent_findings(self, limit: int = 30) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                """SELECT x.*, f.host, f.proc_name, f.provider FROM findings x
                JOIN flows f ON f.id=x.flow_id ORDER BY x.ts DESC, x.id DESC LIMIT ?""",
                (max(1, min(200, limit)),),
            ).fetchall()
            return [dict(row) for row in rows]

    def recent_file_events(self, limit: int = 50) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM file_events ORDER BY ts DESC LIMIT ?", (max(1, min(300, limit)),)
            ).fetchall()
            return [dict(row) for row in rows]

    def count_file_events(self) -> int:
        with self._lock:
            return int(self._conn.execute("SELECT COUNT(*) AS n FROM file_events").fetchone()["n"])

    def stats(self) -> dict[str, Any]:
        now = time.time()
        local_midnight = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0).timestamp()
        with self._lock:
            row = self._conn.execute(
                """SELECT COUNT(*) AS total,
                SUM(CASE WHEN category LIKE 'ai_%' THEN 1 ELSE 0 END) AS ai,
                SUM(CASE WHEN risk >= 70 THEN 1 ELSE 0 END) AS high,
                SUM(CASE WHEN blocked=1 THEN 1 ELSE 0 END) AS blocked,
                SUM(req_bytes) AS bytes,
                SUM(CASE WHEN pid IS NOT NULL THEN 1 ELSE 0 END) AS attributed
                FROM flows WHERE ts >= ?""",
                (local_midnight,),
            ).fetchone()
            severity_rows = self._conn.execute(
                "SELECT severity, COUNT(*) AS n FROM flows WHERE ts >= ? GROUP BY severity", (local_midnight,)
            ).fetchall()
            host_rows = self._conn.execute(
                """SELECT host, provider, COUNT(*) AS n, MAX(risk) AS max_risk FROM flows
                WHERE ts >= ? GROUP BY host ORDER BY n DESC LIMIT 6""",
                (local_midnight,),
            ).fetchall()
            proc_rows = self._conn.execute(
                """SELECT proc_name, pid, COUNT(*) AS n, MAX(risk) AS max_risk FROM flows
                WHERE ts >= ? AND proc_name != '' GROUP BY proc_name, pid ORDER BY n DESC LIMIT 6""",
                (local_midnight,),
            ).fetchall()
            recent = self._conn.execute(
                "SELECT ts, category, risk, blocked FROM flows WHERE ts >= ?", (now - 86400,)
            ).fetchall()
            file_count = self._conn.execute(
                "SELECT COUNT(*) AS n FROM file_events WHERE ts >= ?", (local_midnight,)
            ).fetchone()["n"]
            finding_rows = self._conn.execute(
                """SELECT rule_id, title, COUNT(*) AS n FROM findings WHERE ts >= ?
                GROUP BY rule_id ORDER BY n DESC LIMIT 6""",
                (local_midnight,),
            ).fetchall()
        severity = {key: 0 for key in ("info", "low", "medium", "high", "critical")}
        for item in severity_rows:
            severity[item["severity"]] = item["n"]
        buckets = [{"hour": i, "total": 0, "ai": 0, "high": 0} for i in range(24)]
        start = now - 86400
        for item in recent:
            idx = int((item["ts"] - start) // 3600)
            if 0 <= idx < 24:
                buckets[idx]["total"] += 1
                if str(item["category"]).startswith("ai_"):
                    buckets[idx]["ai"] += 1
                if item["risk"] >= 70 or item["blocked"]:
                    buckets[idx]["high"] += 1
        return {
            "today": {
                "total": row["total"] or 0,
                "ai": row["ai"] or 0,
                "high": row["high"] or 0,
                "blocked": row["blocked"] or 0,
                "bytes": row["bytes"] or 0,
                "attributed": row["attributed"] or 0,
                "file_events": file_count or 0,
            },
            "severity": severity,
            "top_hosts": [dict(r) for r in host_rows],
            "top_procs": [dict(r) for r in proc_rows],
            "top_rules": [dict(r) for r in finding_rows],
            "series": buckets,
        }

    def purge_older_than(self, days: int) -> int:
        cutoff = time.time() - max(1, days) * 86400
        with self._lock, self._conn:
            cur = self._conn.execute("DELETE FROM flows WHERE ts < ?", (cutoff,))
            self._conn.execute("DELETE FROM file_events WHERE ts < ?", (cutoff,))
            return int(cur.rowcount or 0)

    def clear_all(self) -> None:
        with self._lock, self._conn:
            for table in ("findings", "flows", "file_events", "canaries", "audit_chain"):
                self._conn.execute(f"DELETE FROM {table}")
            self._conn.execute("UPDATE meta SET value='GENESIS' WHERE key='last_hash'")
            self._last_hash = "GENESIS"

    def verify_chain(self) -> dict[str, Any]:
        with self._lock:
            rows = self._conn.execute("SELECT * FROM audit_chain ORDER BY id").fetchall()
        prev = "GENESIS"
        for index, row in enumerate(rows):
            expected = hashlib.sha256((prev + row["summary"]).encode("utf-8")).hexdigest()
            if row["prev_hash"] != prev or row["hash"] != expected:
                return {"valid": False, "entries": len(rows), "broken_at": row["id"], "index": index}
            prev = row["hash"]
        return {"valid": True, "entries": len(rows), "head": prev}

    def export_jsonl(self, target: Path) -> dict[str, Any]:
        target.parent.mkdir(parents=True, exist_ok=True)
        count = 0
        with self._lock:
            flow_rows = self._conn.execute("SELECT * FROM flows ORDER BY id").fetchall()
            finding_rows = self._conn.execute("SELECT * FROM findings ORDER BY id").fetchall()
            file_rows = self._conn.execute("SELECT * FROM file_events ORDER BY id").fetchall()
            canary_rows = self._conn.execute("SELECT * FROM canaries ORDER BY id").fetchall()
            chain = self.verify_chain()
        findings_by_flow: dict[int, list[dict[str, Any]]] = {}
        for row in finding_rows:
            item = dict(row)
            findings_by_flow.setdefault(item["flow_id"], []).append(item)
        flow_lines = []
        for row in flow_rows:
            item = dict(row)
            item.pop("enc_req", None)
            item.pop("enc_resp", None)
            item["tags"] = _json_loads(item.get("tags"), [])
            item["app_chain"] = _json_loads(item.get("app_chain"), [])
            item["headers"] = _json_loads(item.get("headers_json"), {})
            item.pop("headers_json", None)
            item["findings"] = findings_by_flow.get(item["id"], [])
            flow_lines.append(item)
        with target.open("w", encoding="utf-8") as handle:
            header = {
                "type": "manifest",
                "product": "EgressScope",
                "exported_at": datetime.now().isoformat(timespec="seconds"),
                "note": "Previews are redacted. Raw bodies are not included in this export.",
                "chain": chain,
            }
            handle.write(json.dumps(header, ensure_ascii=False) + "\n")
            for item in flow_lines:
                handle.write(json.dumps({"type": "flow", **item}, ensure_ascii=False) + "\n")
                count += 1
            for item in file_rows:
                handle.write(json.dumps({"type": "file_event", **dict(item)}, ensure_ascii=False) + "\n")
            for item in canary_rows:
                handle.write(json.dumps({"type": "canary", **dict(item)}, ensure_ascii=False) + "\n")
        return {"path": str(target), "flows": count, "chain_valid": bool(chain.get("valid"))}

    @staticmethod
    def _decode_row(row: dict[str, Any]) -> dict[str, Any]:
        row["tags"] = _json_loads(row.get("tags"), [])
        row["app_chain"] = _json_loads(row.get("app_chain"), [])
        return row


def _json_loads(value: Any, default: Any) -> Any:
    try:
        return json.loads(value) if value else default
    except (TypeError, ValueError):
        return default
