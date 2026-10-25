from __future__ import annotations

import json
import logging
import time
from typing import Any
from urllib.parse import urlsplit

from mitmproxy import http

from .attribution import ProcessInfo
from .policy import Assessment, PolicyEngine, sanitize_headers, severity_for_risk
from .visibility import (
    TUNNEL_NOTE,
    classify_visibility,
    looks_like_tls_failure,
)

log = logging.getLogger(__name__)


class AuditAddon:
    name = "egressscope"

    def __init__(self, app) -> None:
        self.app = app

    def request(self, flow: http.HTTPFlow) -> None:
        if flow.request.method.upper() == "CONNECT":
            return
        settings = self.app.settings
        if not settings.capture_enabled:
            return
        host = flow.request.host or ""
        port = int(flow.request.port or 0)
        if self._is_self(host, port):
            return
        try:
            peername = flow.client_conn.peername
            client_ip = str(peername[0]) if peername else ""
            client_port = int(peername[1]) if peername and len(peername) > 1 else None
            info = self.app.resolver.resolve(client_ip, client_port)
            headers = _flatten_headers(flow.request.headers)
            raw_body, truncated, body_note = _read_message(flow.request, settings.body_limit_bytes)
            assessment = self.app.policy.inspect(
                method=flow.request.method,
                host=host,
                port=port,
                path=flow.request.path,
                headers=headers,
                body=raw_body,
                body_truncated=truncated,
                process_family=info.family if info else "",
                app_kind=info.app_kind if info else "",
            )
            if info is None:
                assessment.tags = sorted(set(assessment.tags + ["unattributed"]))
                assessment.risk = min(100, assessment.risk + 4)
                assessment.severity = severity_for_risk(assessment.risk)
                if settings.blocking_enabled and assessment.risk >= settings.block_risk:
                    assessment.action = "block"
            notes = [n for n in (assessment.note, body_note) if n]
            if info:
                self.app.note_egress(info.pid, info.name)
            flow.metadata["egress"] = {
                "ts": float(flow.request.timestamp_start or time.time()),
                "client_ip": client_ip,
                "client_port": client_port,
                "headers": headers,
                "body": raw_body,
                "body_note": body_note,
                "truncated": truncated,
                "assessment": assessment,
                "process": info,
                "notes": notes,
                "blocked": False,
            }
            if assessment.action == "block":
                payload = {
                    "error": {
                        "type": "egress_policy_blocked",
                        "message": "Request blocked by EgressScope local data-egress policy.",
                        "risk": assessment.risk,
                        "severity": assessment.severity,
                    }
                }
                flow.response = http.Response.make(
                    403,
                    json.dumps(payload, ensure_ascii=False).encode("utf-8"),
                    {
                        "content-type": "application/json; charset=utf-8",
                        "x-egressscope-blocked": "1",
                        "cache-control": "no-store",
                    },
                )
                flow.metadata["egress"]["blocked"] = True
                flow.metadata["egress"]["notes"].append("请求已被 EgressScope 拦截，未发送到上游")
                self.app.note_blocked()
                log.warning("blocked egress host=%s pid=%s risk=%s", host, info.pid if info else None, assessment.risk)
        except Exception:
            log.exception("request capture failed for %s", host)

    def response(self, flow: http.HTTPFlow) -> None:
        self._finalize(flow)

    def error(self, flow: http.HTTPFlow) -> None:
        state = flow.metadata.get("egress")
        if not state:
            self._record_tunnel_failure(flow)
            return
        self._finalize(flow, error=True)

    def websocket_message(self, flow: http.HTTPFlow) -> None:
        # Handshake is captured as a normal HTTP flow; message bodies are intentionally not persisted.
        return

    def _record_tunnel_failure(self, flow: http.HTTPFlow) -> None:
        """Persist a metadata-only row for a CONNECT tunnel that never opened."""
        try:
            if flow.metadata.get("egress") or flow.metadata.get("egress_saved"):
                return
            if flow.request.method.upper() != "CONNECT":
                return
            if not self.app.settings.capture_enabled:
                return
            flow.metadata["egress_saved"] = True
            error_text = str(flow.error.msg) if flow.error else ""
            client_ip = ""
            client_port = None
            info: ProcessInfo | None = None
            try:
                peername = flow.client_conn.peername
                client_ip = str(peername[0]) if peername else ""
                client_port = int(peername[1]) if peername and len(peername) > 1 else None
                info = self.app.resolver.resolve(client_ip, client_port)
            except Exception:
                info = None
            record = build_tunnel_record(
                host=flow.request.host or "",
                port=int(flow.request.port or 0),
                scheme=flow.request.scheme or "https",
                ts=float(flow.request.timestamp_start or time.time()),
                error=error_text,
                tls_failure=looks_like_tls_failure(error_text),
                client_ip=client_ip,
                client_port=client_port,
                info=info,
            )
            flow_id = self.app.store.insert_flow(record, [])
            if info:
                self.app.note_flow_saved(flow_id, info.pid)
        except Exception:
            log.exception("tunnel failure record failed")

    def _finalize(self, flow: http.HTTPFlow, error: bool = False) -> None:
        state = flow.metadata.get("egress")
        if not state or flow.metadata.get("egress_saved"):
            return
        flow.metadata["egress_saved"] = True
        assessment: Assessment = state["assessment"]
        info: ProcessInfo | None = state["process"]
        settings = self.app.settings
        try:
            resp = flow.response
            resp_body: bytes | None = None
            resp_note = ""
            body_note = ""
            status = 0
            resp_preview = ""
            resp_findings = []
            resp_headers: dict[str, str] = {}
            resp_bytes = 0
            duration_ms = 0
            if resp is not None:
                status = int(resp.status_code)
                resp_headers_raw = _flatten_headers(resp.headers)
                resp_headers = sanitize_headers(resp.headers.items(multi=True))
                cl = _content_length(resp.headers)
                resp_bytes = cl if cl is not None else len(resp.content or b"")
                if not state["blocked"]:
                    resp_body, resp_trunc, resp_note = _read_message(resp, settings.body_limit_bytes)
                    body_note = resp_note
                    if resp_body:
                        resp_preview, resp_findings = self.app.policy.inspect_response(
                            headers=resp_headers_raw,
                            body=resp_body,
                            status=status,
                            path=assessment.path,
                        )
                else:
                    resp_preview = "EgressScope blocked this request locally."
                if resp.timestamp_end:
                    duration_ms = max(0, int((resp.timestamp_end - state["ts"]) * 1000))
            elif error and flow.error:
                resp_note = "代理错误：" + _sanitize_note(str(flow.error.msg))[:300]
            if not duration_ms:
                duration_ms = max(0, int((time.time() - state["ts"]) * 1000))
            error_text = str(flow.error.msg) if error and flow.error else ""

            request_content: bytes | None = state.get("body")
            request_headers: dict[str, str] = state.get("headers") or {}
            should_store = bool(
                settings.store_bodies
                and request_content is not None
                and (assessment.is_ai() or assessment.risk >= 25 or bool(assessment.findings))
            )
            enc_req = None
            enc_resp = None
            try:
                if should_store and request_content:
                    enc_req = self.app.box.encrypt(request_content, b"req")
                if should_store and resp_body:
                    enc_resp = self.app.box.encrypt(resp_body, b"resp")
            except Exception:
                log.exception("body encryption failed")
            request_preview = assessment.req_preview
            if not assessment.is_ai() and assessment.risk < 25:
                request_preview = request_preview[:1200]
            notes = list(state.get("notes") or [])
            if resp_note:
                notes.append(resp_note)
            if resp is not None and getattr(resp, "stream", False):
                notes.append("响应正文采用流式传输，未保存")
            tls = _tls_label(flow)
            scheme = flow.request.scheme or ""
            tls_terminated = True
            if scheme.lower() == "https":
                try:
                    tls_terminated = bool(getattr(flow.client_conn, "tls_established", False))
                except Exception:
                    tls_terminated = True
            visibility, visibility_reason = classify_visibility(
                blocked=bool(state["blocked"]),
                is_connect=flow.request.method.upper() == "CONNECT",
                websocket=bool(flow.websocket),
                has_response=resp is not None,
                status=status,
                method=flow.request.method,
                scheme=scheme,
                body_captured=resp_body is not None,
                body_note=body_note,
                request_body_note=str(state.get("body_note") or ""),
                error=error_text,
                tls_failure=looks_like_tls_failure(error_text),
                tls_terminated=tls_terminated,
            )
            record: dict[str, Any] = {
                "ts": state["ts"],
                "method": flow.request.method,
                "scheme": flow.request.scheme,
                "host": flow.request.host,
                "port": int(flow.request.port or 0),
                "path": assessment.path,
                "status": status,
                "req_bytes": len(request_content) if request_content is not None else _content_length(flow.request.headers) or 0,
                "resp_bytes": resp_bytes,
                "duration_ms": duration_ms,
                "content_type": request_headers.get("content-type", ""),
                "app_kind": info.app_kind if info else "",
                "category": assessment.category,
                "provider": assessment.provider,
                "endpoint_kind": assessment.endpoint_kind,
                "model": assessment.model,
                "risk": assessment.risk,
                "severity": assessment.severity,
                "action": "blocked" if state["blocked"] else assessment.action,
                "blocked": state["blocked"],
                "req_preview": request_preview,
                "resp_preview": resp_preview,
                "req_sha": _sha(request_content),
                "resp_sha": _sha(resp_body),
                "enc_req": enc_req,
                "enc_resp": enc_resp,
                "client_ip": state["client_ip"],
                "client_port": state["client_port"],
                "tls": tls,
                "tags": sorted(set(assessment.tags + [f.category for f in assessment.findings + resp_findings])),
                "headers_json": json.dumps(
                    {"request": assessment.headers_preview, "response": resp_headers},
                    ensure_ascii=False,
                ),
                "note": "；".join(dict.fromkeys(n for n in notes if n))[:500],
                "coverage": "proxy-error" if error and resp is None else ("websocket" if flow.websocket else "proxied"),
                "visibility": visibility,
                "visibility_reason": visibility_reason,
            }
            if info:
                record.update(info.as_record())
            else:
                record["pid"] = None
            findings = [f.as_dict() for f in assessment.findings + resp_findings]
            flow_id = self.app.store.insert_flow(record, findings)
            if info:
                self.app.note_flow_saved(flow_id, info.pid)
        except Exception:
            log.exception("flow finalize failed for %s", flow.request.host)

    def _is_self(self, host: str, port: int) -> bool:
        if port == int(getattr(self.app, "web_port", -1) or -1):
            return host in ("127.0.0.1", "localhost", "::1")
        if port == int(getattr(self.app, "listen_port", -1) or -1):
            return host in ("127.0.0.1", "localhost", "::1")
        return False


def build_tunnel_record(
    *,
    host: str,
    port: int,
    scheme: str = "https",
    ts: float | None = None,
    error: str = "",
    tls_failure: bool = False,
    client_ip: str = "",
    client_port: int | None = None,
    info: ProcessInfo | None = None,
) -> dict[str, Any]:
    """Build a metadata-only flow record for an unopened CONNECT tunnel."""
    visibility, reason = classify_visibility(
        is_connect=True,
        has_response=False,
        scheme=scheme,
        error=error,
        tls_failure=tls_failure,
    )
    note = TUNNEL_NOTE if tls_failure or looks_like_tls_failure(error) else (
        "CONNECT 隧道未能建立，仅记录连接元数据，未获得请求内容。"
    )
    tags = ["tunnel-unseen"]
    if info is None:
        tags.append("unattributed")
    record: dict[str, Any] = {
        "ts": float(ts or time.time()),
        "method": "CONNECT",
        "scheme": scheme or "https",
        "host": host or "",
        "port": int(port or 0),
        "path": "",
        "status": 0,
        "req_bytes": 0,
        "resp_bytes": 0,
        "duration_ms": 0,
        "content_type": "",
        "app_kind": info.app_kind if info else "",
        "category": "other",
        "provider": "",
        "endpoint_kind": "",
        "model": "",
        "risk": 0,
        "severity": "info",
        "action": "observe",
        "blocked": False,
        "req_preview": "",
        "resp_preview": "",
        "req_sha": "",
        "resp_sha": "",
        "enc_req": None,
        "enc_resp": None,
        "client_ip": client_ip,
        "client_port": client_port,
        "tls": "",
        "tags": tags,
        "headers_json": "{}",
        "note": note,
        "coverage": "tunnel",
        "visibility": visibility,
        "visibility_reason": reason,
    }
    if info:
        record.update(info.as_record())
    else:
        record["pid"] = None
    return record


def _flatten_headers(headers) -> dict[str, str]:
    result: dict[str, str] = {}
    try:
        items = headers.items(multi=True)
    except TypeError:
        items = headers.items()
    for key, value in items:
        low = key.lower()
        result[low] = (result[low] + ", " + value) if low in result else value
    return result


def _content_length(headers) -> int | None:
    value = headers.get("content-length")
    if value is None:
        return None
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return None


def _read_message(message, limit: int) -> tuple[bytes | None, bool, str]:
    if getattr(message, "stream", False):
        return None, True, "正文为流式传输，未捕获"
    declared = _content_length(message.headers)
    if declared is not None and declared > limit:
        return None, True, f"正文 {declared:,} 字节，超过捕获上限 {limit:,}，未保存"
    try:
        content = message.content
    except Exception:
        return None, False, "正文读取失败"
    if content is None:
        return b"", False, ""
    if len(content) > limit:
        return content[:limit], True, f"正文超过捕获上限 {limit:,}，仅分析前 {limit:,} 字节且不保存原文"
    return content, False, ""


def _sha(value: bytes | None) -> str:
    if not value:
        return ""
    from .crypto import sha256_hex

    return sha256_hex(value)


def _sanitize_note(value: str) -> str:
    from .policy import redact_text

    return redact_text(value)


def _tls_label(flow: http.HTTPFlow) -> str:
    conn = flow.client_conn
    if not getattr(conn, "tls_established", False):
        return "http" if flow.request.scheme == "http" else "unknown"
    version = str(getattr(conn, "tls_version", "") or "TLS")
    cipher = str(getattr(conn, "cipher_name", "") or "")
    alpn = str(getattr(conn, "alpn_proto_negotiated", "") or "")
    parts = [version]
    if cipher:
        parts.append(cipher)
    if alpn:
        parts.append(alpn)
    return " / ".join(parts)
