from __future__ import annotations

import html
import json
import logging
import mimetypes
import secrets
import threading
import time
from datetime import datetime
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

from . import __version__
from .paths import resource_dir
from .system import env_snippet, proxy_state

log = logging.getLogger(__name__)


def _autostart_status(app) -> dict:
    try:
        from .system import autostart_status

        return autostart_status(app.paths)
    except Exception:
        return {}

ALLOWED_SETTINGS = {
    "capture_enabled",
    "blocking_enabled",
    "block_risk",
    "store_bodies",
    "retention_days",
    "file_guard_enabled",
    "canary_enabled",
    "file_guard_interval",
    "upstream_proxy",
    "inherit_system_proxy",
    "autostart_enabled",
    "onboarded",
}


class WebServer:
    def __init__(self, app) -> None:
        self.app = app
        self.token = secrets.token_urlsafe(24)
        self.port = 0
        self.httpd: ThreadingHTTPServer | None = None
        self.thread: threading.Thread | None = None
        self.error = ""
        self.started_at = time.time()
        self._chain_cache: tuple[float, dict] = (0.0, {})
        self._ca_cache: tuple[float, bool] = (0.0, False)

    def start(self) -> int:
        from .system import find_free_port, is_port_free

        desired = int(self.app.settings.web_port)
        self.port = desired if is_port_free("127.0.0.1", desired) else find_free_port("127.0.0.1", desired + 1)
        self.app.web_port = self.port
        self.httpd = ThreadingHTTPServer(("127.0.0.1", self.port), WebHandler)
        self.httpd.egress_app = self.app
        self.httpd.egress_web = self
        self.httpd.daemon_threads = True
        self.thread = threading.Thread(target=self.httpd.serve_forever, name="egressscope-web", daemon=True)
        self.thread.start()
        log.info("dashboard listening on http://127.0.0.1:%s", self.port)
        return self.port

    def stop(self) -> None:
        if self.httpd:
            self.httpd.shutdown()
            self.httpd.server_close()
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=5)
        self.httpd = None
        self.thread = None

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}/"

    def chain_status(self) -> dict:
        now = time.time()
        if now - self._chain_cache[0] < 15:
            return self._chain_cache[1]
        try:
            result = self.app.store.verify_chain()
        except Exception as exc:
            result = {"valid": False, "entries": 0, "error": type(exc).__name__}
        self._chain_cache = (now, result)
        return result

    def ca_installed(self) -> bool:
        now = time.time()
        if now - self._ca_cache[0] < 30:
            return self._ca_cache[1]
        try:
            from .system import ca_info, is_ca_installed

            info = ca_info(self.app.paths.ca_cert_pem)
            value = is_ca_installed(info.get("sha1", ""))
        except Exception:
            value = False
        self._ca_cache = (now, value)
        return value


class WebHandler(BaseHTTPRequestHandler):
    server_version = "EgressScope"
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt: str, *args) -> None:
        log.debug("web %s - %s", self.address_string(), fmt % args)

    # ---------- plumbing ----------
    @property
    def app(self):
        return self.server.egress_app

    @property
    def web(self) -> WebServer:
        return self.server.egress_web

    def _allowed_host(self) -> bool:
        host = self.headers.get("Host", "")
        if not host:
            return False
        name = host.split(":", 1)[0].lower().strip("[]")
        if name not in ("127.0.0.1", "localhost", "::1"):
            return False
        return True

    def _authorized(self) -> bool:
        supplied = self.headers.get("X-Egress-Token", "")
        if not supplied:
            supplied = parse_qs(urlsplit(self.path).query).get("token", [""])[0]
        return bool(supplied) and secrets.compare_digest(supplied, self.web.token)

    def _security_headers(self) -> None:
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Cache-Control", "no-store")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
        )

    def _send_bytes(self, body: bytes, status: int = 200, content_type: str = "application/octet-stream", extra: dict | None = None) -> None:
        self.send_response(status)
        self._security_headers()
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        if extra:
            for key, value in extra.items():
                self.send_header(key, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _send_json(self, payload: Any, status: int = 200) -> None:
        body = json.dumps(payload, ensure_ascii=False, default=str).encode("utf-8")
        self._send_bytes(body, status, "application/json; charset=utf-8")

    def _error(self, status: int, message: str) -> None:
        self._send_json({"ok": False, "error": message, "status": status}, status)

    def _read_json(self, limit: int = 1_000_000) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0 or length > limit:
            return {}
        raw = self.rfile.read(length)
        try:
            data = json.loads(raw)
            return data if isinstance(data, dict) else {}
        except (ValueError, TypeError):
            return {}

    def _serve_html(self, filename: str, bootstrap: dict | None = None) -> None:
        path = resource_dir() / filename
        if not path.exists():
            self._error(500, f"missing web asset: {filename}")
            return
        text = path.read_text(encoding="utf-8")
        if bootstrap is not None:
            payload = json.dumps(bootstrap, ensure_ascii=False).replace("<", "\\u003c")
            text = text.replace("__EGRESS_BOOTSTRAP__", payload)
        body = text.encode("utf-8")
        self._send_bytes(body, 200, "text/html; charset=utf-8")

    # ---------- HTTP ----------
    def do_HEAD(self) -> None:
        self.do_GET()

    def do_GET(self) -> None:
        try:
            if not self._allowed_host():
                self._error(403, "Host not allowed")
                return
            parsed = urlsplit(self.path)
            path = parsed.path
            if path in ("/", "/index.html"):
                self._serve_html("dashboard.html", self._bootstrap())
                return
            if path in ("/intro", "/intro.html"):
                self._serve_html("intro.html")
                return
            if path == "/favicon.ico":
                self._send_bytes(b"", 204, "image/x-icon")
                return
            if path == "/api/health":
                self._send_json({"ok": True, "product": "EgressScope", "version": __version__, "uptime": int(time.time() - self.web.started_at)})
                return
            if path == "/api/ca.pem":
                cert = self.app.paths.ca_cert_pem
                if not cert.exists():
                    self._error(404, "CA not generated")
                    return
                self._send_bytes(
                    cert.read_bytes(),
                    200,
                    "application/x-pem-file",
                    {"Content-Disposition": 'attachment; filename="egressscope-ca-cert.pem"'},
                )
                return
            if path.startswith("/api/") and not self._authorized():
                self._error(401, "Missing or invalid session token")
                return
            if path == "/api/status":
                self._send_json(self._status())
            elif path == "/api/stats":
                self._send_json({"ok": True, "stats": self.app.store.stats()})
            elif path == "/api/flows":
                self._flows(parsed.query)
            elif path.startswith("/api/flows/"):
                self._flow_detail(path)
            elif path == "/api/findings":
                self._send_json({"ok": True, "findings": self.app.store.recent_findings(40)})
            elif path == "/api/file-events":
                self._send_json({
                    "ok": True,
                    "events": self.app.store.recent_file_events(80),
                    "total": self.app.store.count_file_events(),
                })
            elif path == "/api/canaries":
                self._send_json({"ok": True, "canaries": self.app.store.list_canaries()})
            elif path == "/api/env":
                text = env_snippet(self.app.listen_port, self.app.paths.ca_cert_pem)
                self._send_json({"ok": True, "text": text})
            elif path == "/api/export":
                self._export()
            else:
                self._error(404, "Not found")
        except Exception:
            log.exception("web GET failed")
            self._error(500, "Internal error")

    def do_POST(self) -> None:
        try:
            if not self._allowed_host():
                self._error(403, "Host not allowed")
                return
            if not self._authorized():
                self._error(401, "Missing or invalid session token")
                return
            path = urlsplit(self.path).path
            if path == "/api/settings":
                data = self._read_json()
                patch = {k: v for k, v in data.items() if k in ALLOWED_SETTINGS}
                if not patch:
                    self._error(400, "No editable settings supplied")
                    return
                result = self.app.update_settings(patch)
                self._send_json({"ok": True, **result})
            elif path == "/api/clear":
                data = self._read_json()
                if str(data.get("confirm", "")) != "DELETE":
                    self._error(400, "Confirmation required")
                    return
                result = self.app.clear_data()
                self._send_json({"ok": True, **result})
            else:
                self._error(404, "Not found")
        except Exception as exc:
            log.exception("web POST failed")
            self._error(400 if isinstance(exc, ValueError) else 500, str(exc) or "Internal error")

    # ---------- payloads ----------
    def _bootstrap(self) -> dict:
        settings = self.app.settings
        return {
            "product": "EgressScope",
            "version": __version__,
            "token": self.web.token,
            "proxy": f"http://127.0.0.1:{self.app.listen_port}",
            "webPort": self.web.port,
            "introUrl": "/intro",
            "caUrl": "/api/ca.pem",
            "settings": {
                "capture_enabled": settings.capture_enabled,
                "blocking_enabled": settings.blocking_enabled,
                "block_risk": settings.block_risk,
                "store_bodies": settings.store_bodies,
                "retention_days": settings.retention_days,
                "file_guard_enabled": settings.file_guard_enabled,
                "canary_enabled": settings.canary_enabled,
                "file_guard_interval": settings.file_guard_interval,
                "upstream_proxy": settings.upstream_proxy,
                "inherit_system_proxy": settings.inherit_system_proxy,
                "onboarded": settings.onboarded,
            },
        }

    def _status(self) -> dict:
        settings = self.app.settings
        try:
            from .system import ca_info

            ca = ca_info(self.app.paths.ca_cert_pem)
            installed = self.web.ca_installed()
        except Exception:
            ca, installed = {}, False
        proxy = self.app.proxy.status()
        state = proxy_state(self.app.listen_port)
        fileguard = self.app.fileguard.status() if getattr(self.app, "fileguard", None) else {}
        return {
            "ok": True,
            "version": __version__,
            "uptime": int(time.time() - self.web.started_at),
            "proxy": proxy,
            "web": {"port": self.web.port, "url": self.web.url},
            "capture": settings.capture_enabled,
            "settings": {
                "blocking_enabled": settings.blocking_enabled,
                "block_risk": settings.block_risk,
                "store_bodies": settings.store_bodies,
                "body_limit_bytes": settings.body_limit_bytes,
                "retention_days": settings.retention_days,
                "capture_enabled": settings.capture_enabled,
                "file_guard_enabled": settings.file_guard_enabled,
                "canary_enabled": settings.canary_enabled,
                "upstream_proxy": settings.upstream_proxy,
                "inherit_system_proxy": settings.inherit_system_proxy,
                "autostart_enabled": settings.autostart_enabled,
                "onboarded": settings.onboarded,
            },
            "ca": {**ca, "installed": installed},
            "system_proxy": state,
            "autostart": _autostart_status(self.app),
            "config_reload": self.app.config_reload,
            "fileguard": fileguard,
            "chain": self.web.chain_status(),
            "data_dir": str(self.app.paths.data),
            "coverage": {
                "proxied": "经本地代理的 HTTP/HTTPS 流量",
                "decryptable": "信任 EgressScope CA 且未启用证书固定的 TLS 流量",
                "not_visible": "直连、未信任 CA、证书固定、mTLS、QUIC/HTTP3、E2EE 内容、服务/SYSTEM 进程",
                "file_guard": "基于打开文件句柄的抽样关联（Beta），不是完整读取审计",
            },
        }

    def _flows(self, query: str) -> None:
        params = parse_qs(query)
        def get(name: str, default: str = "") -> str:
            return params.get(name, [default])[0]
        try:
            limit = int(get("limit", "60"))
            offset = int(get("offset", "0"))
        except ValueError:
            limit, offset = 60, 0
        since = None
        try:
            since_hours = float(get("since_hours", "0") or 0)
            if since_hours > 0:
                since = time.time() - since_hours * 3600
        except ValueError:
            pass
        pid = None
        if get("pid"):
            try:
                pid = int(get("pid"))
            except ValueError:
                pid = None
        min_risk = None
        if get("min_risk"):
            try:
                min_risk = int(get("min_risk"))
            except ValueError:
                min_risk = None
        flows, total = self.app.store.list_flows(
            limit=min(200, max(1, limit)),
            offset=max(0, offset),
            q=get("q")[:200],
            severity=get("severity")[:60],
            category=get("category")[:40],
            ai_only=get("ai", "") in ("1", "true", "yes"),
            since=since,
            pid=pid,
            min_risk=min_risk,
            blocked_only=get("blocked", "") in ("1", "true", "yes"),
        )
        self._send_json({"ok": True, "flows": flows, "total": total, "limit": limit, "offset": offset})

    def _flow_detail(self, path: str) -> None:
        try:
            flow_id = int(path.rsplit("/", 1)[-1])
        except ValueError:
            self._error(400, "Invalid flow id")
            return
        reveal = parse_qs(urlsplit(self.path).query).get("reveal", [""])[0] in ("1", "true", "yes")
        detail = self.app.store.flow_detail(flow_id, reveal=reveal)
        if not detail:
            self._error(404, "Flow not found")
            return
        try:
            detail["headers"] = json.loads(detail.pop("headers_json", "{}") or "{}")
        except (ValueError, TypeError):
            detail["headers"] = {}
        self._send_json({"ok": True, "flow": detail, "revealed": reveal})

    def _export(self) -> None:
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        target = self.app.paths.exports / f"egressscope-{stamp}.jsonl"
        result = self.app.store.export_jsonl(target)
        body = target.read_bytes()
        self._send_bytes(
            body,
            200,
            "application/x-ndjson; charset=utf-8",
            {"Content-Disposition": f'attachment; filename="egressscope-{stamp}.jsonl"'},
        )
