"""End-to-end smoke test for EgressScope.

Runs a temporary local app instance, a self-signed mock AI endpoint, and a
requests client through the real proxy/CA stack. No system proxy or root CA
changes are made. Run from the project root:

    .venv/Scripts/python.exe tests/smoke_test.py
"""
from __future__ import annotations

import contextlib
import datetime
import json
import os
import re
import socket
import ssl
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from ai_audit.paths import AppPaths
from app import EgressApp

PASSED: list[str] = []
FAILED: list[str] = []


def check(name: str, condition: bool, detail: str = "") -> None:
    if condition:
        PASSED.append(name)
        print(f"  PASS  {name}")
    else:
        FAILED.append(name)
        print(f"  FAIL  {name}{(' — ' + detail) if detail else ''}")
        if os.environ.get("GITHUB_ACTIONS"):
            print(f"::error title=EgressScope test::{name} {detail}".rstrip())


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def wait_for(predicate, timeout: float = 12.0, interval: float = 0.15):
    end = time.time() + timeout
    while time.time() < end:
        value = predicate()
        if value:
            return value
        time.sleep(interval)
    return None


def port_is_closed(port: int, timeout: float = 0.2) -> bool:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=timeout):
            return False
    except OSError:
        return True


def make_certificate(directory: Path) -> tuple[Path, Path]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
    ])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=2))
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
                x509.IPAddress(__import__("ipaddress").ip_address("127.0.0.1")),
            ]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    cert_path = directory / "mock-cert.pem"
    key_path = directory / "mock-key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    return cert_path, key_path


class MockAIHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):  # noqa: N802
        return

    def _read_body(self) -> bytes:
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        return self.rfile.read(length) if length else b""

    def _json(self, status: int, payload: dict) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):  # noqa: N802
        body = self._read_body()
        if self.path.endswith("/v1/chat/completions"):
            self._json(200, {
                "id": "chatcmpl-local-test",
                "object": "chat.completion",
                "model": "local-audit-test",
                "choices": [{"index": 0, "message": {"role": "assistant", "content": "ack"}, "finish_reason": "stop"}],
                "usage": {"prompt_tokens": 32, "completion_tokens": 1, "total_tokens": 33},
                "echo_bytes": len(body),
            })
        else:
            self._json(200, {"ok": True, "received": len(body)})

    def do_GET(self):  # noqa: N802
        self._json(200, {"ok": True, "path": self.path})


@contextlib.contextmanager
def mock_tls_server(cert: Path, key: Path):
    port = free_port()
    server = ThreadingHTTPServer(("127.0.0.1", port), MockAIHandler)
    server.daemon_threads = True
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(cert), str(key))
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, name="smoke-mock-ai", daemon=True)
    thread.start()
    try:
        yield port
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def parse_bootstrap(page: str) -> dict:
    match = re.search(r"const BOOT = (\{.*?\});", page, re.S)
    assert match, "dashboard bootstrap payload not found"
    return json.loads(match.group(1))


SECRET_KEY = "sk-proj-smokeTestOnly1234567890abcdefghijklmnopqrstuvwxyz"
CN_ID = "110105199003071239"


def sensitive_payload(second: bool = False) -> dict:
    marker = "second pass " if second else ""
    return {
        "model": "gpt-4o-mini",
        "temperature": 0.2,
        "stream": False,
        "messages": [
            {
                "role": "user",
                "content": (
                    f"{marker}Please summarize this private workspace. "
                    f"API key: {SECRET_KEY}\n"
                    f"Customer identity: {CN_ID}\n"
                    "Source file: C:\\Users\\ww\\project\\billing\\secrets.env\n"
                    "```python\nprint('internal-only')\n```"
                ),
            }
        ],
    }


def run_key_artifact(home: str) -> str:
    """Return the Run-key value if this test run leaked one into the real registry."""
    if sys.platform != "win32":
        return ""
    import winreg

    try:
        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Run",
            0,
            winreg.KEY_READ,
        ) as key:
            value = str(winreg.QueryValueEx(key, "EgressScope")[0])
    except OSError:
        return ""
    return value if home in value else ""


def run() -> None:
    print("\nEgressScope smoke test")
    print("======================")
    before_proxy_port = None
    with tempfile.TemporaryDirectory(prefix="egressscope-smoke-") as temp:
        temp_dir = Path(temp)
        cert_path, key_path = make_certificate(temp_dir)
        app: EgressApp | None = None
        session = requests.Session()
        session.trust_env = False
        try:
            with mock_tls_server(cert_path, key_path) as mock_port:
                home = temp_dir / "home"
                paths = AppPaths(home)
                app = EgressApp(paths)
                app.settings.listen_port = free_port()
                app.settings.web_port = free_port()
                app.settings.file_guard_enabled = False
                app.settings.canary_enabled = False
                app.settings.insecure_upstream = True
                app.settings.retention_days = 3
                app.settings.inherit_system_proxy = False
                app.settings.upstream_proxy = ""
                app.settings.autostart_enabled = False
                app.start()

                check("app starts without startup error", not app.startup_error, app.startup_error)
                leaked = run_key_artifact(str(home))
                check("test run leaves the real Run key alone", not leaked, leaked)
                check("proxy webserver exposes a token", bool(app.web.token))
                check("CA files generated", paths.ca_cert_pem.exists() and paths.ca_pem.exists())
                ca_info = app.ca_status(force=True)
                check("CA common name is product branded", ca_info.get("common_name") == "EgressScope Local Audit CA", str(ca_info))
                env_text = app.env_text()
                check("agent env contains local proxy", f"127.0.0.1:{app.listen_port}" in env_text)
                check("agent env contains CA path", str(paths.ca_cert_pem) in env_text)

                web_base = app.web.url.rstrip("/")
                page_resp = session.get(web_base + "/", timeout=10)
                check("dashboard returns 200", page_resp.status_code == 200, str(page_resp.status_code))
                page = page_resp.text
                check("dashboard injects bootstrap", "__EGRESS_BOOTSTRAP__" not in page and "const BOOT = {" in page)
                check("dashboard includes core views", all(label in page for label in ("流量审计", "风险发现", "覆盖范围", "策略与设置")))
                bootstrap = parse_bootstrap(page)
                token = bootstrap.get("token", "")
                check("bootstrap token is non-empty", bool(token))
                intro_resp = session.get(web_base + "/intro", timeout=10)
                check("intro returns 200", intro_resp.status_code == 200, str(intro_resp.status_code))
                check("intro explains honest limits", "覆盖边界" in intro_resp.text and "证书固定" in intro_resp.text and "未签名" in intro_resp.text)
                tech_resp = session.get(web_base + "/tech", timeout=10)
                check("technical page returns 200", tech_resp.status_code == 200, str(tech_resp.status_code))
                check(
                    "technical page documents data path and limits",
                    "127.0.0.1:7890" in tech_resp.text and "检测，不重定向" in tech_resp.text and "未在 CI" in tech_resp.text,
                )
                ca_resp = session.get(web_base + "/api/ca.pem", timeout=10)
                check("public CA is downloadable", ca_resp.status_code == 200 and b"BEGIN CERTIFICATE" in ca_resp.content)
                unauth = session.get(web_base + "/api/status", timeout=10)
                check("API rejects missing token", unauth.status_code == 401, str(unauth.status_code))
                bad_host = session.get(web_base + "/api/status", headers={"Host": "evil.example", "X-Egress-Token": token}, timeout=10)
                check("API rejects non-loopback Host", bad_host.status_code == 403, str(bad_host.status_code))
                api_headers = {"X-Egress-Token": token}
                status_resp = session.get(web_base + "/api/status", headers=api_headers, timeout=10)
                status_payload = status_resp.json()
                check("status API reports running proxy", status_resp.status_code == 200 and status_payload.get("proxy", {}).get("running"))
                check("status API is honest about invisible traffic", "QUIC" in status_payload.get("coverage", {}).get("not_visible", ""))
                network_status = status_payload.get("network") or {}
                check(
                    "status API reports bounded bypass observation",
                    network_status.get("enabled") is True and "透明重定向" in network_status.get("note", ""),
                    str(network_status)[:200],
                )
                network_api = session.get(web_base + "/api/network?limit=10", headers={"X-Egress-Token": token}, timeout=10)
                network_payload = network_api.json()
                check(
                    "network API returns observation metadata",
                    network_api.status_code == 200
                    and network_payload.get("enabled") is True
                    and isinstance(network_payload.get("events"), list)
                    and "counts" in network_payload,
                    str(network_payload)[:200],
                )

                proxies = {"http": f"http://127.0.0.1:{app.listen_port}", "https": f"http://127.0.0.1:{app.listen_port}"}
                url = f"https://localhost:{mock_port}/v1/chat/completions"
                r1 = session.post(
                    url,
                    json=sensitive_payload(),
                    headers={"Authorization": f"Bearer {SECRET_KEY}", "User-Agent": "EgressScope-Smoke/1.0"},
                    proxies=proxies,
                    verify=str(paths.ca_cert_pem),
                    timeout=20,
                )
                check("HTTPS request through local CA succeeds", r1.status_code == 200, f"{r1.status_code}: {r1.text[:160]}")
                check("upstream response is reachable", r1.json().get("id") == "chatcmpl-local-test")

                def get_flows():
                    return app.store.list_flows(limit=20)[0]

                flows = wait_for(lambda: get_flows(), timeout=12)
                check("flow was persisted", bool(flows))
                flow = flows[0] if flows else {}
                check("host and path captured", flow.get("host") == "localhost" and flow.get("path") == "/v1/chat/completions", str(flow)[:200])
                proc_name = str(flow.get("proc_name") or "")
                expected_proc = Path(sys.executable).name
                if sys.platform == "win32":
                    check(
                        "client process attributed",
                        bool(flow.get("pid")) and proc_name == expected_proc,
                        f"pid={flow.get('pid')} proc={proc_name} expected={expected_proc}",
                    )
                elif sys.platform == "linux" and not app.resolver.last_error:
                    check(
                        "client process attributed",
                        bool(flow.get("pid")) and proc_name.lower().startswith("python"),
                        f"pid={flow.get('pid')} proc={proc_name} resolve_error={app.resolver.last_error}",
                    )
                else:
                    check(
                        "process attribution degrades without TCP owner access",
                        not flow.get("pid") or proc_name.lower().startswith("python"),
                        f"pid={flow.get('pid')} proc={proc_name} resolve_error={app.resolver.last_error}",
                    )
                check("AI local endpoint classified", flow.get("category") == "ai_local", str(flow.get("category")))
                check("captured flow is graded full", flow.get("visibility") == "full" and not flow.get("visibility_reason"), str(flow.get("visibility")))
                check("model extracted", flow.get("model") == "gpt-4o-mini", str(flow.get("model")))
                check("TLS metadata captured", "TLS" in str(flow.get("tls", "")), str(flow.get("tls")))
                check("risk reaches critical", int(flow.get("risk") or 0) >= 85, str(flow.get("risk")))
                check("finding includes OpenAI key", any(f.get("rule_id") == "secret.openai_key" for f in app.store.flow_detail(flow["id"], reveal=False)["findings"]))
                check("finding includes CN ID", any(f.get("rule_id") == "pii.cn_id" for f in app.store.flow_detail(flow["id"], reveal=False)["findings"]))
                detail_locked = session.get(web_base + f"/api/flows/{flow['id']}", headers=api_headers, timeout=10).json()["flow"]
                check("detail hides raw bodies without reveal", detail_locked.get("request_body") is None and detail_locked["body_available"]["request"] is True)
                check("detail never returns ciphertext", "enc_req" not in detail_locked and "enc_resp" not in detail_locked)
                check("preview redacts secret", SECRET_KEY not in detail_locked.get("req_preview", "") and CN_ID not in detail_locked.get("req_preview", ""), detail_locked.get("req_preview", "")[:160])
                check("headers are sanitized", "sk-proj-smoke" not in json.dumps(detail_locked.get("headers", {}), ensure_ascii=False))
                reveal_payload = session.get(web_base + f"/api/flows/{flow['id']}?reveal=1", headers=api_headers, timeout=10).json()["flow"]
                check("explicit reveal decrypts request body", SECRET_KEY in (reveal_payload.get("request_body") or ""))
                check("explicit reveal decrypts response body", "chatcmpl-local-test" in (reveal_payload.get("response_body") or ""))

                r2 = session.post(
                    url,
                    json={"model": "gpt-4o-mini", "messages": [{"role": "user", "content": "hello local model"}]},
                    proxies=proxies,
                    verify=str(paths.ca_cert_pem),
                    timeout=20,
                )
                check("second benign HTTPS request succeeds", r2.status_code == 200)
                wait_for(lambda: len(get_flows()) >= 2, timeout=10)
                other = session.get(
                    f"https://localhost:{mock_port}/telemetry?source=smoke",
                    proxies=proxies,
                    verify=str(paths.ca_cert_pem),
                    timeout=20,
                )
                check("non-AI HTTPS request succeeds through proxy", other.status_code == 200)
                wait_for(lambda: len(get_flows()) >= 3, timeout=10)
                all_flows = get_flows()
                check("all flows persisted", len(all_flows) >= 3, str(len(all_flows)))
                check("non-AI traffic classified as other", any(f.get("category") == "other" for f in all_flows))

                stats = session.get(web_base + "/api/stats", headers=api_headers, timeout=10).json()["stats"]
                check("stats count today's traffic", stats["today"]["total"] >= 3 and stats["today"]["ai"] >= 2, json.dumps(stats["today"]))
                check("stats expose visibility distribution", int((stats.get("visibility") or {}).get("full", 0)) >= 3, str(stats.get("visibility")))
                app.store.add_net_event({
                    "ts": time.time(),
                    "kind": "quic",
                    "pid": flow.get("pid"),
                    "proc_name": "smoke-agent.exe",
                    "remote_ip": "203.0.113.10",
                    "remote_port": 443,
                    "protocol": "udp",
                    "domain": "",
                    "confidence": "candidate",
                    "note": "QUIC test candidate",
                })
                observed = session.get(web_base + "/api/network?limit=10", headers=api_headers, timeout=10).json()
                observed_events = observed.get("events") or []
                check(
                    "network API exposes stored candidates with counts",
                    any(e.get("remote_ip") == "203.0.113.10" and e.get("kind") == "quic" for e in observed_events)
                    and int((observed.get("counts") or {}).get("quic", 0)) >= 1,
                    str(observed)[:200],
                )
                listed = session.get(web_base + "/api/flows?limit=10&ai=1", headers=api_headers, timeout=10).json()
                check("flow filter API works", listed["total"] >= 2 and all(f["category"].startswith("ai_") for f in listed["flows"]))
                findings = session.get(web_base + "/api/findings", headers=api_headers, timeout=10).json()["findings"]
                check("findings API returns findings", len(findings) >= 2)
                file_events = session.get(web_base + "/api/file-events", headers=api_headers, timeout=10).json()
                check("file event API reports its total", file_events.get("total") == len(file_events.get("events", [])))

                chain = app.store.verify_chain()
                check("audit hash chain valid", chain.get("valid") is True and chain.get("entries", 0) >= 3, str(chain))

                export_resp = session.get(web_base + "/api/export", headers=api_headers, timeout=20)
                check("evidence export succeeds", export_resp.status_code == 200 and len(export_resp.content) > 100)
                exported = export_resp.content.decode("utf-8")
                check("export manifest marks redaction", '"Previews are redacted' in exported)
                check("export excludes raw secret", SECRET_KEY not in exported and CN_ID not in exported)
                check("export excludes ciphertext", "enc_req" not in exported and "enc_resp" not in exported)

                enable = session.post(
                    web_base + "/api/settings",
                    headers={**api_headers, "Content-Type": "application/json"},
                    json={"blocking_enabled": True, "block_risk": 70},
                    timeout=10,
                ).json()
                check("settings API enables blocking", enable["settings"]["blocking_enabled"] is True and enable["settings"]["block_risk"] == 70)
                r3 = session.post(
                    url,
                    json=sensitive_payload(second=True),
                    headers={"Authorization": f"Bearer {SECRET_KEY}"},
                    proxies=proxies,
                    verify=str(paths.ca_cert_pem),
                    timeout=20,
                )
                check("high-risk request is blocked locally", r3.status_code == 403 and r3.headers.get("x-egressscope-blocked") == "1", f"{r3.status_code} {r3.text[:120]}")
                blocked_flows = wait_for(lambda: [f for f in get_flows() if f.get("blocked")], timeout=10)
                check("blocked action persisted", bool(blocked_flows))
                check("blocked flow marked critical", bool(blocked_flows) and blocked_flows[0]["severity"] == "critical")
                session.post(
                    web_base + "/api/settings",
                    headers={**api_headers, "Content-Type": "application/json"},
                    json={"blocking_enabled": False, "block_risk": 85},
                    timeout=10,
                )
                paused = session.post(
                    web_base + "/api/settings",
                    headers={**api_headers, "Content-Type": "application/json"},
                    json={"network_watch_enabled": False},
                    timeout=10,
                ).json()
                check("network watch setting hot-disables the observer", paused["settings"]["network_watch_enabled"] is False and app.netwatch.status()["enabled"] is False)
                resumed = session.post(
                    web_base + "/api/settings",
                    headers={**api_headers, "Content-Type": "application/json"},
                    json={"network_watch_enabled": True},
                    timeout=10,
                ).json()
                check("network watch setting hot-enables the observer", resumed["settings"]["network_watch_enabled"] is True and app.netwatch.status()["enabled"] is True)

                before_proxy_port = app.listen_port
                app.stop(restore_proxy=False)
                app = None
                check("proxy port closed after shutdown", bool(wait_for(lambda: port_is_closed(before_proxy_port), timeout=5.0)))
                check("web port closed after shutdown", bool(wait_for(lambda: port_is_closed(int(bootstrap["webPort"])), timeout=5.0)))
        finally:
            session.close()
            if app is not None:
                app.stop(restore_proxy=False)

    print("\n======================")
    print(f"{len(PASSED)} passed, {len(FAILED)} failed")
    if FAILED:
        for name in FAILED:
            print("  - " + name)
        raise SystemExit(1)


if __name__ == "__main__":
    run()
