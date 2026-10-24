"""Upstream chaining test for EgressScope.

Starts a real app instance and a minimal CONNECT relay acting as the upstream
HTTP proxy. Verifies that audited traffic is forwarded through the relay and
that automatic system-proxy inheritance only accepts active loopback proxies.

Run from the project root:

    .venv/Scripts/python.exe tests/upstream_test.py
"""
from __future__ import annotations

import select
import socket
import socketserver
import sys
import tempfile
import threading
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
TESTS = Path(__file__).resolve().parent
if str(TESTS) not in sys.path:
    sys.path.insert(0, str(TESTS))

import requests

from ai_audit import system
from ai_audit.paths import AppPaths
from app import EgressApp
from smoke_test import free_port, make_certificate, mock_tls_server, sensitive_payload, wait_for

RELAY_CALLS: list[str] = []
PASSED: list[str] = []
FAILED: list[str] = []


def check(name: str, condition: bool, detail: str = "") -> None:
    (PASSED if condition else FAILED).append(name)
    suffix = f" — {detail}" if detail and not condition else ""
    print(f"  {'PASS' if condition else 'FAIL'}  {name}{suffix}")


class ConnectRelay(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        self.request.settimeout(15)
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = self.request.recv(4096)
            if not chunk:
                return
            data += chunk
        first_line = data.split(b"\r\n", 1)[0].decode("latin-1")
        RELAY_CALLS.append(first_line)
        if not first_line.upper().startswith("CONNECT "):
            self.request.sendall(b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n")
            return
        target = first_line.split()[1]
        host, _, port = target.rpartition(":")
        upstream = socket.create_connection((host.strip("[]"), int(port)), timeout=15)
        try:
            self.request.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            peers = {self.request: upstream, upstream: self.request}
            while True:
                readable, _, _ = select.select(list(peers), [], [], 15)
                if not readable:
                    return
                for source in readable:
                    chunk = source.recv(65536)
                    if not chunk:
                        return
                    peers[source].sendall(chunk)
        finally:
            upstream.close()


def start_relay() -> tuple[socketserver.ThreadingTCPServer, int]:
    port = free_port()
    relay = socketserver.ThreadingTCPServer(("127.0.0.1", port), ConnectRelay)
    relay.daemon_threads = True
    threading.Thread(target=relay.serve_forever, name="upstream-relay", daemon=True).start()
    return relay, port


def check_detect_loopback() -> None:
    cases = [
        ({"available": True, "enabled": True, "pac_active": False, "server": "127.0.0.1:7890"}, "http://127.0.0.1:7890"),
        ({"available": True, "enabled": True, "pac_active": False, "server": "http=127.0.0.1:7890;https=127.0.0.1:7891"}, "http://127.0.0.1:7890"),
        ({"available": True, "enabled": True, "pac_active": False, "server": "localhost:1080"}, "http://localhost:1080"),
        ({"available": True, "enabled": True, "pac_active": True, "server": "127.0.0.1:7890"}, ""),
        ({"available": True, "enabled": False, "pac_active": False, "server": "127.0.0.1:7890"}, ""),
        ({"available": True, "enabled": True, "pac_active": False, "server": "10.0.0.5:7890"}, ""),
        ({"available": True, "enabled": True, "pac_active": False, "server": "127.0.0.1:7890"}, ""),
    ]
    for index, (state, expected) in enumerate(cases[:-1]):
        with mock.patch.object(system, "proxy_state", return_value=state):
            actual = system.detect_loopback_proxy()
        check(f"detect loopback proxy case {index + 1}", actual == expected, f"{actual!r} != {expected!r}")
    with mock.patch.object(system, "proxy_state", return_value=cases[-1][0]):
        actual = system.detect_loopback_proxy({7890})
    check("detect loopback proxy honors excluded ports", actual == "", actual)


def run() -> None:
    print("\nEgressScope upstream chaining test")
    print("==================================")
    check_detect_loopback()
    with tempfile.TemporaryDirectory(prefix="egressscope-upstream-") as temp:
        temp_dir = Path(temp)
        cert_path, key_path = make_certificate(temp_dir)
        relay, relay_port = start_relay()
        app: EgressApp | None = None
        session = requests.Session()
        session.trust_env = False
        try:
            with mock_tls_server(cert_path, key_path) as mock_port:
                paths = AppPaths(temp_dir / "home")
                app = EgressApp(paths)
                app.settings.listen_port = free_port()
                app.settings.web_port = free_port()
                app.settings.file_guard_enabled = False
                app.settings.canary_enabled = False
                app.settings.insecure_upstream = True
                app.settings.inherit_system_proxy = False
                app.settings.upstream_proxy = f"http://127.0.0.1:{relay_port}"
                app.start()
                check("app starts with configured upstream", not app.startup_error, app.startup_error)
                status = app.proxy.status()
                check("status reports configured upstream", status.get("upstream_proxy") == f"http://127.0.0.1:{relay_port}", str(status))
                check("status reports configured source", status.get("upstream_source") == "configured", str(status))

                response = session.post(
                    f"https://localhost:{mock_port}/v1/chat/completions",
                    json=sensitive_payload(),
                    headers={"Authorization": "Bearer sk-upstream-test", "User-Agent": "EgressScope-Upstream/1.0"},
                    proxies={"http": f"http://127.0.0.1:{app.listen_port}", "https": f"http://127.0.0.1:{app.listen_port}"},
                    verify=str(paths.ca_cert_pem),
                    timeout=30,
                )
                check("audited HTTPS request succeeds through upstream", response.status_code == 200, f"{response.status_code}: {response.text[:160]}")
                check("upstream relay accepted a CONNECT", any(line.upper().startswith("CONNECT ") for line in RELAY_CALLS), str(RELAY_CALLS))
                check(
                    "upstream relay received the audited host",
                    any(f"localhost:{mock_port}" in line or f"127.0.0.1:{mock_port}" in line for line in RELAY_CALLS),
                    str(RELAY_CALLS),
                )

                flows = wait_for(lambda: app.store.list_flows(limit=5)[0] or None, timeout=10) or []
                check("flow is still captured with an upstream", bool(flows))
                if flows:
                    check("captured flow keeps the target host", "localhost" in str(flows[0].get("host") or ""), str(flows[0].get("host")))
        finally:
            session.close()
            if app is not None:
                app.stop(restore_proxy=False)
            relay.shutdown()
            relay.server_close()

    print("\n==================================")
    print(f"{len(PASSED)} passed, {len(FAILED)} failed")
    if FAILED:
        for name in FAILED:
            print("  - " + name)
        raise SystemExit(1)


if __name__ == "__main__":
    run()
