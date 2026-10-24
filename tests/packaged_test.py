from __future__ import annotations

import datetime
import ipaddress
import json
import os
import re
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

PROJECT = Path(__file__).resolve().parent.parent
EXE = PROJECT / "dist" / "EgressScope.exe"
PASSED: list[str] = []
FAILED: list[str] = []
SECRET_KEY = "sk-proj-packagedTestOnly1234567890abcdefghijklmnopqrstuvwxyz"
CN_ID = "110105199003071239"


def check(name: str, condition: bool, detail: str = "") -> None:
    if condition:
        PASSED.append(name)
        print(f"  PASS  {name}")
    else:
        FAILED.append(name)
        print(f"  FAIL  {name}  {detail}")


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def wait_for(predicate, timeout: float = 12.0, interval: float = 0.2):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            value = predicate()
            if value:
                return value
        except Exception:
            pass
        time.sleep(interval)
    return None


def port_is_closed(port: int, timeout: float = 0.25) -> bool:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=timeout):
            return False
    except OSError:
        return True


def make_certificate(directory: Path) -> tuple[Path, Path]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
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
                x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
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
                "id": "chatcmpl-packaged-test",
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


def start_mock(cert: Path, key: Path) -> tuple[ThreadingHTTPServer, int]:
    port = free_port()
    server = ThreadingHTTPServer(("127.0.0.1", port), MockAIHandler)
    server.daemon_threads = True
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(cert), str(key))
    server.socket = context.wrap_socket(server.socket, server_side=True)
    threading.Thread(target=server.serve_forever, name="mock-ai", daemon=True).start()
    return server, port


def parse_bootstrap(page: str) -> dict:
    match = re.search(r"const BOOT = (\{.*?\});", page, re.S)
    if not match:
        raise AssertionError("bootstrap payload not found")
    return json.loads(match.group(1))


def sensitive_payload(second: bool = False) -> dict:
    marker = "second pass " if second else ""
    return {
        "model": "gpt-4o-mini",
        "temperature": 0.2,
        "stream": False,
        "messages": [{
            "role": "user",
            "content": (
                f"{marker}Please summarize this private workspace. "
                f"API key: {SECRET_KEY}\n"
                f"Customer identity: {CN_ID}\n"
                "Source file: C:\\Users\\ww\\project\\billing\\secrets.env\n"
                "```python\nprint('internal-only')\n```"
            ),
        }],
    }


def main() -> int:
    print("\nPackaged EXE end-to-end test")
    print("===========================")
    check("packaged executable exists", EXE.exists(), str(EXE))
    if not EXE.exists():
        return 1
    check("packaged executable has plausible size", EXE.stat().st_size > 20 * 1024 * 1024, f"{EXE.stat().st_size} bytes")

    with tempfile.TemporaryDirectory(prefix="egressscope-exe-", ignore_cleanup_errors=True) as temp:
        temp_dir = Path(temp)
        cert_path, key_path = make_certificate(temp_dir)
        home = temp_dir / "home"
        proxy_port = free_port()
        web_port = free_port()
        mock_server, mock_port = start_mock(cert_path, key_path)
        env = {k: v for k, v in os.environ.items() if k.lower() not in ("http_proxy", "https_proxy", "all_proxy")}
        log_file = None
        proc = None
        session = requests.Session()
        session.trust_env = False
        try:
            print(f"  starting {EXE.name} (proxy {proxy_port}, web {web_port}) ...")
            proc = subprocess.Popen(
                [
                    str(EXE),
                    "--headless",
                    "--home", str(home),
                    "--proxy-port", str(proxy_port),
                    "--web-port", str(web_port),
                    "--insecure-upstream",
                    "--no-inherit-upstream",
                    "--no-fileguard",
                    "--log-level", "INFO",
                ],
                cwd=str(PROJECT),
                env=env,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            web_base = f"http://127.0.0.1:{web_port}"

            def healthy():
                resp = session.get(web_base + "/api/health", timeout=2)
                return resp.status_code == 200 and resp.json().get("ok")

            started = wait_for(healthy, timeout=120)
            if not started:
                log_files = list((home / "data" / "logs").glob("*.log")) if (home / "data" / "logs").exists() else []
                tail = ""
                if log_files:
                    log_file = log_files[0]
                    tail = "\n".join(log_file.read_text(encoding="utf-8", errors="replace").splitlines()[-30:])
                check("packaged app becomes healthy", False, f"proc={proc.poll()} log={tail}")
                return 1
            check("packaged app becomes healthy", True)
            health = session.get(web_base + "/api/health", timeout=5).json()
            check("health identifies product and version", health.get("product") == "EgressScope" and bool(health.get("version")), str(health))

            page_resp = session.get(web_base + "/", timeout=10)
            check("bundled dashboard asset loads", page_resp.status_code == 200 and "流量审计" in page_resp.text, str(page_resp.status_code))
            check("dashboard bootstrap injected", "__EGRESS_BOOTSTRAP__" not in page_resp.text and "const BOOT = {" in page_resp.text)
            bootstrap = parse_bootstrap(page_resp.text)
            token = bootstrap.get("token", "")
            check("session token issued", bool(token))
            api_headers = {"X-Egress-Token": token}
            check("bootstrap reports configured ports", int(bootstrap.get("webPort") or 0) == web_port, str(bootstrap.get("webPort")))

            intro = session.get(web_base + "/intro", timeout=10)
            check("bundled intro page loads", intro.status_code == 200 and "覆盖边界" in intro.text and "证书固定" in intro.text, str(intro.status_code))
            check("bundled intro explains upstream chaining", "127.0.0.1:7890" in intro.text and "回环" in intro.text, "upstream copy missing")

            unauth = session.get(web_base + "/api/status", timeout=10)
            check("API rejects missing token", unauth.status_code == 401, str(unauth.status_code))
            status = wait_for(
                lambda: (
                    lambda s: s if s.get("proxy", {}).get("running") is True and (s.get("ca") or {}).get("common_name") else None
                )(session.get(web_base + "/api/status", headers=api_headers, timeout=10).json()),
                timeout=60,
            ) or {}
            check("packaged proxy is running", status.get("proxy", {}).get("running") is True, json.dumps(status.get("proxy", {}), ensure_ascii=False))
            check("no-inherit keeps upstream direct", status.get("proxy", {}).get("upstream_proxy") == "", str(status.get("proxy", {}).get("upstream_proxy")))
            check("status exposes honest coverage", "QUIC" in status.get("coverage", {}).get("not_visible", ""))
            ca_info = status.get("ca", {})
            check("local CA generated in packaged mode", ca_info.get("common_name") == "EgressScope Local Audit CA", str(ca_info)[:200])

            ca_path = home / "data" / "certs" / "mitmproxy-ca-cert.pem"
            ca_resp = wait_for(
                lambda: (
                    lambda r: r if r.status_code == 200 and b"BEGIN CERTIFICATE" in r.content else None
                )(session.get(web_base + "/api/ca.pem", timeout=10)),
                timeout=30,
            )
            check("public CA is downloadable", ca_resp is not None)
            check("downloaded CA matches data dir", bool(ca_resp) and ca_path.exists() and ca_path.read_bytes().strip() == ca_resp.content.strip())

            proxies = {"http": f"http://127.0.0.1:{proxy_port}", "https": f"http://127.0.0.1:{proxy_port}"}
            url = f"https://localhost:{mock_port}/v1/chat/completions"
            upstream = session.post(
                url,
                json=sensitive_payload(),
                headers={"Authorization": f"Bearer {SECRET_KEY}", "User-Agent": "EgressScope-Packaged/1.0"},
                proxies=proxies,
                verify=str(ca_path),
                timeout=30,
            )
            check("HTTPS through packaged proxy succeeds", upstream.status_code == 200, f"{upstream.status_code}: {upstream.text[:160]}")
            check("upstream response is correct", upstream.json().get("id") == "chatcmpl-packaged-test", upstream.text[:160])

            def get_flows():
                resp = session.get(web_base + "/api/flows?limit=20", headers=api_headers, timeout=5)
                return resp.json().get("flows") or []

            flows = wait_for(get_flows, timeout=20)
            check("packaged capture persists a flow", bool(flows))
            if not flows:
                return 1
            flow = flows[0]
            check("host and path captured", flow.get("host") == "localhost" and flow.get("path") == "/v1/chat/completions", str(flow)[:200])
            check("client PID attributed", int(flow.get("pid") or 0) > 0 and flow.get("proc_name") == "python.exe", f"pid={flow.get('pid')} proc={flow.get('proc_name')}")
            check("AI endpoint classified", flow.get("category") == "ai_local", str(flow.get("category")))
            check("model extracted", flow.get("model") == "gpt-4o-mini", str(flow.get("model")))
            check("TLS metadata captured", "TLS" in str(flow.get("tls", "")), str(flow.get("tls")))
            check("risk reaches critical", int(flow.get("risk") or 0) >= 85, str(flow.get("risk")))

            detail_resp = session.get(web_base + f"/api/flows/{flow['id']}", headers=api_headers, timeout=10).json()
            detail = detail_resp["flow"]
            rule_ids = {f.get("rule_id") for f in detail.get("findings", [])}
            check("packaged scanner finds OpenAI key", "secret.openai_key" in rule_ids, str(rule_ids))
            check("packaged scanner finds CN ID", "pii.cn_id" in rule_ids, str(rule_ids))
            check("locked detail hides raw bodies", detail.get("request_body") is None and detail.get("body_available", {}).get("request") is True)
            check("preview redacts secret", SECRET_KEY not in detail.get("req_preview", "") and CN_ID not in detail.get("req_preview", ""))
            check("ciphertext is never returned", "enc_req" not in detail and "enc_resp" not in detail)

            revealed_resp = session.get(web_base + f"/api/flows/{flow['id']}?reveal=1", headers=api_headers, timeout=10).json()
            revealed = revealed_resp["flow"]
            check("explicit reveal decrypts request", SECRET_KEY in (revealed.get("request_body") or ""))
            check("explicit reveal decrypts response", "chatcmpl-packaged-test" in (revealed.get("response_body") or ""))

            findings = session.get(web_base + "/api/findings", headers=api_headers, timeout=10).json().get("findings") or []
            check("findings endpoint returns findings", len(findings) >= 2, str(len(findings)))
            stats = session.get(web_base + "/api/stats", headers=api_headers, timeout=10).json().get("stats") or {}
            check("stats endpoint counts traffic", (stats.get("today") or {}).get("total", 0) >= 1, json.dumps(stats)[:200])

            export = session.get(web_base + "/api/export", headers=api_headers, timeout=20)
            exported = export.content.decode("utf-8", errors="replace")
            check("evidence export succeeds", export.status_code == 200 and len(exported) > 100, str(export.status_code))
            check("export redacts raw secret", SECRET_KEY not in exported and CN_ID not in exported)
            check("export excludes ciphertext", "enc_req" not in exported and "enc_resp" not in exported)

            chain = wait_for(
                lambda: (
                    lambda c: c if c.get("valid") is True and int(c.get("entries") or 0) >= 1 else None
                )(session.get(web_base + "/api/status", headers=api_headers, timeout=10).json().get("chain", {})),
                timeout=20,
            )
            check("audit hash chain valid", bool(chain), str(chain))

            enable = session.post(
                web_base + "/api/settings",
                headers={**api_headers, "Content-Type": "application/json"},
                json={"blocking_enabled": True, "block_risk": 70},
                timeout=10,
            ).json()
            check("packaged settings API updates", (enable.get("settings") or {}).get("blocking_enabled") is True, str(enable)[:200])
            blocked = session.post(
                url,
                json=sensitive_payload(second=True),
                headers={"Authorization": f"Bearer {SECRET_KEY}"},
                proxies=proxies,
                verify=str(ca_path),
                timeout=30,
            )
            check("packaged blocking returns 403", blocked.status_code == 403, f"{blocked.status_code}: {blocked.text[:120]}")
            check("block response is marked", blocked.headers.get("x-egressscope-blocked") == "1", str(dict(blocked.headers))[:200])

            log_files = list((home / "data" / "logs").glob("*.log"))
            if log_files:
                log_text = "\n".join(p.read_text(encoding="utf-8", errors="replace") for p in log_files)
                check("packaged log has no traceback", "Traceback" not in log_text, log_text[-500:])
                check("packaged log records proxy startup", "proxy" in log_text.lower(), log_text[-300:])
        finally:
            session.close()
            mock_server.shutdown()
            mock_server.server_close()
            if proc is not None and proc.poll() is None:
                subprocess.run(["taskkill", "/PID", str(proc.pid), "/T", "/F"], capture_output=True, timeout=20)
                try:
                    proc.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=5)
            check("proxy port released after exit", bool(wait_for(lambda: port_is_closed(proxy_port), timeout=10)))
            check("web port released after exit", bool(wait_for(lambda: port_is_closed(web_port), timeout=10)))

    print("\n===========================")
    print(f"{len(PASSED)} passed, {len(FAILED)} failed")
    if FAILED:
        for name in FAILED:
            print(f"  - {name}")
    return 1 if FAILED else 0


if __name__ == "__main__":
    sys.exit(main())
