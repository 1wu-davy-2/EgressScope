"""Hermetic tests for proxy-bypass / QUIC / DNS observation.

No real PowerShell, network scan, registry, or scheduled task is executed.
Run from the project root:

    python tests/netwatch_test.py
"""
from __future__ import annotations

import json
import os
import socket
import sys
import tempfile
import time
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ai_audit.crypto import SecureBox
from ai_audit.netwatch import (
    NetworkWatch,
    classify_destination,
    is_public_remote,
    parse_dns_cache,
)
from ai_audit.store import Store

PASSED: list[str] = []
FAILED: list[str] = []


def check(name: str, condition: bool, detail: str = "") -> None:
    if condition:
        PASSED.append(name)
        print(f"  PASS  {name}")
    else:
        FAILED.append(name)
        print(f"  FAIL  {name}{(' — ' + detail) if detail else ''}")


def conn(ip: str, port: int, pid: int | None = 1234, kind: int = socket.SOCK_STREAM):
    return SimpleNamespace(raddr=(ip, port), laddr=("127.0.0.1", 50000), pid=pid, type=kind)


class FakeResolver:
    def __init__(self, fail: bool = False) -> None:
        self.calls: list[int] = []
        self.fail = fail

    def info_for_pid(self, pid: int):
        self.calls.append(pid)
        if self.fail:
            from ai_audit.attribution import ProcessInfo

            raise FileNotFoundError(pid)
        from ai_audit.attribution import ProcessInfo

        return ProcessInfo(pid=pid, name="agent.exe", exe=r"C:\Apps\agent.exe", app_kind="agent")


class FakeStore:
    def __init__(self) -> None:
        self.records: list[dict] = []

    def add_net_event(self, record: dict) -> int:
        self.records.append(dict(record))
        return len(self.records)

    def net_event_counts(self, since: float | None = None) -> dict[str, int]:
        counts = {"direct_tcp": 0, "quic": 0, "dns": 0}
        for record in self.records:
            if since is not None and float(record.get("ts") or 0) < since:
                continue
            key = str(record.get("kind") or "")
            counts[key] = counts.get(key, 0) + 1
        counts["total"] = sum(v for k, v in counts.items() if k != "total")
        return counts

    def list_net_events(self, limit: int = 50, kind: str = "") -> list[dict]:
        rows = [r for r in self.records if not kind or r.get("kind") == kind]
        return list(reversed(rows))[:limit]


def make_app(store=None, enabled: bool = True, resolver=None, capture: bool = True):
    return SimpleNamespace(
        settings=SimpleNamespace(
            network_watch_enabled=enabled,
            capture_enabled=capture,
            listen_port=8899,
            web_port=8898,
        ),
        store=store if store is not None else FakeStore(),
        resolver=resolver if resolver is not None else FakeResolver(),
        listen_port=8899,
        web_port=8898,
    )


def test_public_filter() -> None:
    check("loopback is not public", not is_public_remote("127.0.0.1"))
    check("private IPv4 is not public", not is_public_remote("10.1.2.3"))
    check("private IPv6 is not public", not is_public_remote("fd00::1"))
    check("link-local is not public", not is_public_remote("169.254.1.2"))
    check("multicast is not public", not is_public_remote("224.0.0.1"))
    check("unspecified is not public", not is_public_remote("0.0.0.0"))
    check("CGNAT is not public", not is_public_remote("100.64.0.1"))
    check("invalid address is not public", not is_public_remote("not-an-ip"))
    check("public IPv4 is public", is_public_remote("8.8.8.8"))
    check("public IPv6 is public", is_public_remote("2606:4700:4700::1111"))


def test_classification() -> None:
    check("udp 443 is quic", classify_destination("udp", 443)[0] == "quic")
    check("quic note is honest", "无法解密" in classify_destination("udp", 443)[1])
    check("tcp 443 is direct", classify_destination("tcp", 443)[0] == "direct_tcp")
    check("tcp 80 is direct", classify_destination("tcp", 80)[0] == "direct_tcp")
    check("tcp 8080 is direct", classify_destination("tcp", 8080)[0] == "direct_tcp")
    check("tcp 8443 is direct", classify_destination("tcp", 8443)[0] == "direct_tcp")
    check("tcp 53 is dns", classify_destination("tcp", 53)[0] == "dns")
    check("udp 53 is dns", classify_destination("udp", 53)[0] == "dns")
    check("tcp 853 is dns", classify_destination("tcp", 853) == ("dns", "仅记录 DNS 目标，不记录查询内容"))
    check("udp 853 is not dns", classify_destination("udp", 853) == ("", ""))
    check("unrelated port ignored", classify_destination("tcp", 22) == ("", ""))
    check("port zero ignored", classify_destination("tcp", 0) == ("", ""))
    check("direct note admits proxies and non-HTTP", "上游代理" in classify_destination("tcp", 443)[1] and "非 HTTP" in classify_destination("tcp", 443)[1])


def test_dns_parser() -> None:
    one = parse_dns_cache({"Entry": "api.example.com", "Data": "1.2.3.4"})
    check("dns parser handles a single dict", one == {"1.2.3.4": "api.example.com"}, str(one))
    many = parse_dns_cache([
        {"Entry": "api.example.com", "Data": "1.2.3.4"},
        {"Entry": "cdn.example.com", "Data": ["5.6.7.8", "2001:db8::1"]},
    ])
    check("dns parser handles a list and data arrays", many.get("5.6.7.8") == "cdn.example.com" and many.get("2001:db8::1") == "cdn.example.com", str(many))
    raw = json.dumps([{"Entry": "json.example.com", "Data": "9.9.9.9"}])
    check("dns parser accepts raw JSON", parse_dns_cache(raw) == {"9.9.9.9": "json.example.com"})
    check("dns parser ignores malformed JSON", parse_dns_cache("{not json") == {})
    check("dns parser ignores non-IP data", parse_dns_cache({"Entry": "x", "Data": "CNAME target"}) == {})
    check("dns parser ignores other shapes", parse_dns_cache(None) == {} and parse_dns_cache(42) == {})
    check("dns parser tolerates non-dict entries", parse_dns_cache([{"Entry": "a", "Data": "1.1.1.1"}, "bad"]) == {"1.1.1.1": "a"})


def test_scan_filters_and_attribution() -> None:
    store = FakeStore()
    resolver = FakeResolver()
    app = make_app(store=store, resolver=resolver)
    watcher = NetworkWatch(app)
    connections = [
        conn("8.8.8.8", 443, 111),
        conn("1.1.1.1", 443, os.getpid()),
        conn("127.0.0.1", 443, 111),
        conn("10.0.0.5", 443, 111),
        conn("8.8.4.4", 22, 111),
        conn("9.9.9.9", 53, 111),
        conn("8.8.8.8", 443, 111, socket.SOCK_DGRAM),
        conn("8.8.8.8", 0, 111),
        conn("1.1.1.1", 8899, 111),
        conn("1.1.1.1", 8443, 222, socket.SOCK_DGRAM),
    ]
    result = watcher.scan_once(
        connections=connections,
        dns_map={"8.8.8.8": "dns.google"},
        now=1_700_000_000.0,
    )
    kinds = [r["kind"] for r in store.records]
    check("scan ignores own pid/private/loopback/irrelevant ports", result["stored"] == 3, str(result) + " " + str(kinds))
    check("scan classifies direct, dns and quic", kinds == ["direct_tcp", "dns", "quic"], str(kinds))
    direct = store.records[0]
    check("direct record includes attribution", direct["pid"] == 111 and direct["proc_name"] == "agent.exe" and direct["app_kind"] == "agent")
    check("direct record includes protocol and confidence", direct["protocol"] == "tcp" and direct["confidence"] == "candidate")
    check("direct record is enriched from DNS cache", direct["domain"] == "dns.google")
    check("dns record has no query content", store.records[1]["note"] == "仅记录 DNS 目标，不记录查询内容")
    check("quic record notes it cannot be decrypted", "无法解密" in store.records[2]["note"])
    check("last scan timestamp is updated", watcher.last_scan_at == 1_700_000_000.0 and not watcher.last_error)
    check("resolver was used for attribution", resolver.calls == [111])

    vanished = FakeStore()
    app2 = make_app(store=vanished, resolver=FakeResolver(fail=True))
    watcher2 = NetworkWatch(app2)
    watcher2.scan_once(connections=[conn("8.8.8.8", 443, 333)], dns_map={}, now=1_700_000_000.0)
    check("vanished pid does not crash the scan", len(vanished.records) == 1 and vanished.records[0]["proc_name"] == "")


def test_in_memory_dedupe() -> None:
    store = FakeStore()
    watcher = NetworkWatch(make_app(store=store))
    one = [conn("8.8.8.8", 443, 444)]
    base = 1_700_000_000.0
    watcher.scan_once(connections=one, dns_map={}, now=base)
    watcher.scan_once(connections=one, dns_map={}, now=base + 100)
    check("duplicate candidate within 600s is skipped", len(store.records) == 1, str(len(store.records)))
    watcher.scan_once(connections=one, dns_map={}, now=base + 601)
    check("candidate is re-emitted after 600s", len(store.records) == 2, str(len(store.records)))


def test_status_and_lifecycle() -> None:
    store = FakeStore()
    app = make_app(store=store)
    watcher = NetworkWatch(app)
    status = watcher.status()
    for key in ("supported", "enabled", "running", "interval", "last_scan_at", "last_error", "counts", "dns", "note"):
        check(f"status has {key}", key in status)
    check("status dns shape", set(status["dns"]) >= {"supported", "cached", "last_at", "error"})
    check("status dns support matches platform", status["dns"]["supported"] == (sys.platform == "win32"))
    check("status note rejects transparent redirects", "透明重定向" in status["note"] and "加密内容" in status["note"])
    check("status is not paused while capture is on", status.get("paused") is False)
    check("network watch starts when enabled", watcher.start() is True and watcher.running is True)
    watcher.stop()
    check("network watch stops", watcher.running is False)
    disabled = NetworkWatch(make_app(enabled=False))
    check("disabled setting prevents start", disabled.start() is False and disabled.status()["enabled"] is False)
    paused_store = FakeStore()
    paused = NetworkWatch(make_app(store=paused_store, capture=False))
    paused_result = paused.scan_once(connections=[conn("8.8.8.8", 443)], dns_map={}, now=1_700_000_000.0)
    check("paused capture prevents start", paused.start() is False and paused.status()["paused"] is True)
    check("paused capture skips scans and writes nothing", paused_result.get("skipped") is True and not paused_store.records)


def test_store_net_events() -> None:
    with tempfile.TemporaryDirectory(prefix="egressscope-netwatch-") as temp:
        directory = Path(temp)
        store = Store(directory / "net.db", SecureBox(directory / "key"))
        now = time.time()
        try:
            record = {
                "ts": now,
                "kind": "direct_tcp",
                "pid": 4321,
                "proc_name": "agent.exe",
                "proc_path": r"C:\Apps\agent.exe",
                "app_kind": "agent",
                "remote_ip": "8.8.8.8",
                "remote_port": 443,
                "protocol": "tcp",
                "domain": "dns.google",
                "confidence": "candidate",
                "note": "direct candidate",
            }
            first = store.add_net_event(record)
            second = store.add_net_event({**record, "ts": now + 120})
            rows = store.list_net_events()
            check("db dedupe keeps one row and the first id", first == second and len(rows) == 1, str(rows))
            check("db dedupe increments seen_count and updates ts", rows[0]["seen_count"] == 2 and rows[0]["ts"] == now + 120, str(rows[0]))
            third = store.add_net_event({**record, "ts": now + 721})
            check("db dedupe inserts after 600s", third != first and len(store.list_net_events()) == 2)
            counts = store.net_event_counts()
            check("net_event_counts includes per-kind and total", counts.get("direct_tcp") == 2 and counts.get("quic") == 0 and counts.get("dns") == 0 and counts.get("total") == 2, str(counts))
            check("net_event_counts honours since", store.net_event_counts(since=now + 300)["total"] == 1)
            target = directory / "export.jsonl"
            store.export_jsonl(target)
            lines = [json.loads(line) for line in target.read_text(encoding="utf-8").splitlines()]
            check("export contains net_event lines", sum(1 for line in lines if line.get("type") == "net_event") == 2)
            check("export manifest marks observation metadata", "local observation metadata" in lines[0].get("note", ""))
            old_ts = now - 10 * 86400
            store.add_net_event({**record, "ts": old_ts, "remote_ip": "9.9.9.9"})
            store.purge_older_than(7)
            check("purge removes old net events", store.net_event_counts()["total"] == 2)
            store.clear_all()
            check("clear_all removes net events", store.net_event_counts()["total"] == 0)
        finally:
            store.close()


def run() -> None:
    print("\nEgressScope network watch test")
    print("=============================")
    test_public_filter()
    test_classification()
    test_dns_parser()
    test_scan_filters_and_attribution()
    test_in_memory_dedupe()
    test_status_and_lifecycle()
    test_store_net_events()
    print("\n=============================")
    print(f"{len(PASSED)} passed, {len(FAILED)} failed")
    if FAILED:
        for name in FAILED:
            print("  - " + name)
        raise SystemExit(1)


if __name__ == "__main__":
    run()
