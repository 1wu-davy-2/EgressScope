"""Focused tests for connection visibility classification and storage.

Run from the project root:

    python tests/visibility_test.py
"""
from __future__ import annotations

import json
import sqlite3
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ai_audit.addon import build_tunnel_record
from ai_audit.attribution import ProcessInfo
from ai_audit.crypto import SecureBox
from ai_audit.store import SCHEMA, Store
from ai_audit.visibility import classify_visibility

PASSED: list[str] = []
FAILED: list[str] = []
SECRET = "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789"


def check(name: str, condition: bool, detail: str = "") -> None:
    if condition:
        PASSED.append(name)
        print(f"  PASS  {name}")
    else:
        FAILED.append(name)
        print(f"  FAIL  {name}{(' — ' + detail) if detail else ''}")


def test_classification() -> None:
    level, reason = classify_visibility(blocked=True)
    check("policy block is blocked", level == "blocked" and "策略" in reason, f"{level} {reason}")

    level, reason = classify_visibility(is_connect=True, scheme="https", error="connection reset by peer")
    check("connect failure is metadata", level == "metadata", level)
    check("connect failure says the tunnel was not established", "隧道" in reason, reason)

    level, reason = classify_visibility(
        is_connect=True,
        scheme="https",
        error="TLS handshake failed: client rejected certificate",
    )
    check("tls connect failure is metadata", level == "metadata", level)
    check("tls caveat mentions pinning, mTLS and local CA", all(x in reason for x in ("证书固定", "mTLS", "本地 CA")), reason)

    level, reason = classify_visibility(error="upstream dial failed " + SECRET)
    check("proxy error without response is error", level == "error", level)
    check("error reason is sanitized", SECRET not in reason and "代理" in reason, reason)

    level, reason = classify_visibility(
        scheme="https",
        has_response=False,
        error="TLS handshake failed: upstream certificate verify error",
    )
    check("non-connect tls failure is metadata", level == "metadata", level)
    check("non-connect tls caveat is honest", "证书固定" in reason and "mTLS" in reason, reason)

    level, reason = classify_visibility(websocket=True, has_response=True, status=101, body_captured=False)
    check("websocket upgrade is partial", level == "partial" and "WebSocket" in reason, f"{level} {reason}")

    level, reason = classify_visibility(has_response=True, scheme="https", tls_terminated=False, body_captured=True, status=200)
    check("https without client tls termination is metadata", level == "metadata", level)
    check("unterminated tls caveat is honest", "证书固定" in reason and "本地 CA" in reason, reason)

    level, reason = classify_visibility(has_response=True, body_captured=True, status=200)
    check("captured response body is full", (level, reason) == ("full", ""), f"{level} {reason}")
    level, _ = classify_visibility(has_response=True, body_captured=True, status=204)
    check("204 empty response is full", level == "full", level)
    level, _ = classify_visibility(has_response=True, body_captured=False, method="HEAD", status=200)
    check("HEAD without body is full", level == "full", level)

    level, reason = classify_visibility(
        has_response=True,
        body_captured=False,
        status=200,
        body_note="正文为流式传输，未捕获",
    )
    check("streaming response is partial", level == "partial" and "流式" in reason, f"{level} {reason}")

    level, reason = classify_visibility(has_response=False)
    check("missing response after request capture is partial", level == "partial" and "未观察到响应" in reason, f"{level} {reason}")

    level, reason = classify_visibility(
        has_response=True,
        body_captured=False,
        status=200,
        body_note="upstream " + SECRET,
    )
    check("body note reason is sanitized", level == "partial" and SECRET not in reason, reason)

    level, reason = classify_visibility(
        has_response=True,
        body_captured=True,
        status=200,
        request_body_note="正文为流式传输，未捕获",
    )
    check("incomplete request body downgrades full", level == "partial" and "请求正文" in reason, f"{level} {reason}")

    level, reason = classify_visibility(
        has_response=True,
        body_captured=True,
        status=204,
        request_body_note="正文超过捕获上限 2,000,000",
    )
    check("incomplete request body is partial even with empty response", level == "partial" and "请求正文" in reason, f"{level} {reason}")


def test_tunnel_record() -> None:
    info = ProcessInfo(pid=4242, name="agent.exe", exe=r"C:\Apps\agent.exe", app_kind="agent")
    record = build_tunnel_record(
        host="api.example.com",
        port=443,
        scheme="https",
        ts=1700000000.0,
        error="TLS handshake failed: client rejected local CA",
        tls_failure=True,
        client_ip="127.0.0.1",
        client_port=50123,
        info=info,
    )
    check("tunnel record is CONNECT", record["method"] == "CONNECT")
    check("tunnel record has tunnel coverage", record["coverage"] == "tunnel" and record["visibility"] == "metadata")
    check("tunnel record keeps pid attribution", record["pid"] == 4242 and record["proc_name"] == "agent.exe")
    check("tunnel record has no request/response previews", not record["req_preview"] and not record["resp_preview"])
    check("tunnel record has no bodies or hashes", record["enc_req"] is None and record["enc_resp"] is None and not record["req_sha"] and not record["resp_sha"])
    check("tunnel record has zero sizes/status", record["status"] == 0 and record["req_bytes"] == 0 and record["resp_bytes"] == 0)
    check("tunnel record is tagged", "tunnel-unseen" in record["tags"])
    check("tunnel record note admits metadata-only", "连接元数据" in record["note"])
    check("tunnel record reason carries the pinning caveat", "证书固定" in record["visibility_reason"], record["visibility_reason"])

    plain = build_tunnel_record(host="plain.example.com", port=443, error="connection reset")
    check("non-tls tunnel failure says tunnel was not established", "隧道未能建立" in plain["visibility_reason"], plain["visibility_reason"])
    check("unattributed tunnel record is marked", "unattributed" in plain["tags"] and plain["pid"] is None)


def make_store(directory: Path) -> Store:
    return Store(directory / "audit.db", SecureBox(directory / "master.key"))


def flow_record(**overrides) -> dict:
    record = {
        "ts": time.time(),
        "method": "POST",
        "scheme": "https",
        "host": "api.example.com",
        "port": 443,
        "path": "/v1/chat/completions",
        "status": 200,
        "category": "ai_service",
        "provider": "OpenAI",
        "risk": 10,
        "severity": "low",
        "action": "observe",
        "visibility": "full",
        "visibility_reason": "",
    }
    record.update(overrides)
    return record


def test_store_visibility() -> None:
    with tempfile.TemporaryDirectory(prefix="egressscope-visibility-") as temp:
        directory = Path(temp)
        store = make_store(directory)
        try:
            inserted = {}
            for key in ("full", "partial", "metadata", "blocked", "error"):
                inserted[key] = store.insert_flow(
                    flow_record(
                        visibility=key,
                        visibility_reason="" if key == "full" else f"reason-{key}",
                        blocked=key == "blocked",
                    ),
                    [],
                )
            rows, total = store.list_flows(limit=20)
            check("list_flows returns visibility fields", total == 5 and all("visibility" in row and "visibility_reason" in row for row in rows), str(total))
            detail = store.flow_detail(inserted["metadata"])
            check("flow_detail includes visibility", detail is not None and detail.get("visibility") == "metadata" and detail.get("visibility_reason") == "reason-metadata")
            stats = store.stats()
            check(
                "stats exposes today's visibility counts",
                stats.get("visibility") == {"full": 1, "partial": 1, "metadata": 1, "blocked": 1, "error": 1},
                str(stats.get("visibility")),
            )
            target = directory / "export.jsonl"
            result = store.export_jsonl(target)
            lines = [json.loads(line) for line in target.read_text(encoding="utf-8").splitlines()]
            manifest = lines[0]
            flows = [line for line in lines if line.get("type") == "flow"]
            check("export includes visibility on flows", len(flows) == 5 and all("visibility" in row for row in flows))
            check("export manifest discloses network observation metadata", "local observation metadata" in manifest.get("note", ""), manifest.get("note", ""))
            check("export reports flow count", result.get("flows") == 5 and result.get("chain_valid") is True, str(result))
        finally:
            store.close()


def test_migration() -> None:
    with tempfile.TemporaryDirectory(prefix="egressscope-visibility-migrate-") as temp:
        directory = Path(temp)
        db_path = directory / "old.db"
        old_schema = SCHEMA.replace(
            "    coverage TEXT NOT NULL DEFAULT 'proxied',\n"
            "    visibility TEXT NOT NULL DEFAULT 'full',\n"
            "    visibility_reason TEXT NOT NULL DEFAULT ''\n",
            "    coverage TEXT NOT NULL DEFAULT 'proxied'\n",
        )
        check("old schema fixture has no visibility columns", "visibility" not in old_schema)
        conn = sqlite3.connect(str(db_path))
        conn.executescript(old_schema)
        conn.execute(
            """INSERT INTO flows(ts, method, scheme, host, port, path, status, coverage)
            VALUES (?, 'GET', 'https', 'legacy.example', 443, '/old', 200, 'proxied')""",
            (time.time() - 60,),
        )
        conn.commit()
        conn.close()

        store = Store(db_path, SecureBox(directory / "master.key"))
        try:
            columns = {row["name"] for row in store._conn.execute("PRAGMA table_info(flows)").fetchall()}
            check("migration adds visibility columns", {"visibility", "visibility_reason"} <= columns, str(columns))
            rows, total = store.list_flows(limit=10)
            check("historical row survives migration", total == 1)
            check(
                "historical row is partial with an honest reason",
                rows[0]["visibility"] == "partial" and rows[0]["visibility_reason"] == "升级前的历史记录未做可见性分级",
                str(rows[0]),
            )
            new_id = store.insert_flow(flow_record(visibility=None), [])
            new_row = store.flow_detail(new_id)
            check("new rows default to full visibility", new_row is not None and new_row["visibility"] == "full")
        finally:
            store.close()


def run() -> None:
    print("\nEgressScope visibility test")
    print("==========================")
    test_classification()
    test_tunnel_record()
    test_store_visibility()
    test_migration()
    print("\n==========================")
    print(f"{len(PASSED)} passed, {len(FAILED)} failed")
    if FAILED:
        for name in FAILED:
            print("  - " + name)
        raise SystemExit(1)


if __name__ == "__main__":
    run()
