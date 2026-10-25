"""Connection visibility classification for captured flows.

The labels are deliberately conservative: a flow is only ``full`` when the
response was actually readable by the local proxy. Tunnel and TLS handshake
failures are metadata-only because EgressScope does not bypass certificate
pinning, mTLS, or a client that rejects the local CA.
"""
from __future__ import annotations

from .policy import redact_text

VISIBILITY_LEVELS = ("full", "partial", "metadata", "blocked", "error")

VISIBILITY_LABELS = {
    "full": "完整",
    "partial": "部分",
    "metadata": "仅元数据",
    "blocked": "已拦截",
    "error": "错误",
}

BLOCKED_REASON = "策略命中，请求已在本地拦截"
TUNNEL_UNSEEN_REASON = "CONNECT 隧道未能建立；仅记录连接元数据，未获得请求内容"
TLS_VISIBILITY_REASON = (
    "TLS 握手失败：可能启用了证书固定、mTLS，或客户端拒绝本地 CA；仅记录连接元数据"
)
TLS_NOT_TERMINATED_REASON = (
    "客户端 TLS 未被本地代理终止：可能启用了证书固定、mTLS，或客户端拒绝本地 CA；仅记录连接元数据"
)
WEBSOCKET_REASON = "WebSocket 握手可见，消息正文未持久化"
BODY_MISSING_REASON = "响应正文未保留（流式、超限或读取失败），仅保留元数据与脱敏预览"
RESPONSE_MISSING_REASON = "请求已捕获，但未观察到响应；仅保留请求元数据"
TUNNEL_NOTE = (
    "本地代理未能建立可解密的 CONNECT 隧道，仅记录连接元数据；"
    "应用可能启用了证书固定、mTLS，或拒绝本地 CA。"
)

_TLS_HINTS = (
    "tls",
    "ssl",
    "handshake",
    "certificate",
    "clienthello",
    "alert",
    "unknown ca",
)


def looks_like_tls_failure(text: str) -> bool:
    value = str(text or "").lower()
    return any(hint in value for hint in _TLS_HINTS)


def _sanitize_reason(text: str, limit: int = 200) -> str:
    return redact_text(str(text or "")).strip()[:limit]


def classify_visibility(
    *,
    blocked: bool = False,
    is_connect: bool = False,
    websocket: bool = False,
    has_response: bool = False,
    status: int = 0,
    method: str = "",
    scheme: str = "",
    body_captured: bool = False,
    body_note: str = "",
    request_body_note: str = "",
    error: str = "",
    tls_failure: bool = False,
    tls_terminated: bool = True,
) -> tuple[str, str]:
    """Return ``(visibility, reason)`` for a completed or failed flow.

    Precedence matters: policy blocks and tunnel failures win over body
    availability; a WebSocket upgrade is partial because message frames are
    intentionally not persisted.
    """
    if blocked:
        return "blocked", BLOCKED_REASON
    if is_connect and not has_response:
        if tls_failure or looks_like_tls_failure(error):
            return "metadata", TLS_VISIBILITY_REASON
        return "metadata", TUNNEL_UNSEEN_REASON
    if not has_response and (
        tls_failure or ((scheme or "").lower() == "https" and looks_like_tls_failure(error))
    ):
        return "metadata", TLS_VISIBILITY_REASON
    if websocket:
        return "partial", WEBSOCKET_REASON
    if not tls_terminated and (scheme or "").lower() == "https":
        return "metadata", TLS_NOT_TERMINATED_REASON
    if has_response:
        if not body_captured and not _body_is_legitimately_empty(method, status):
            reason = _sanitize_reason(body_note, 160) or BODY_MISSING_REASON
            return "partial", reason
        if request_body_note:
            reason = "请求正文未完整保留：" + _sanitize_reason(request_body_note, 150)
            return "partial", reason[:240]
        return "full", ""
    if error:
        detail = _sanitize_reason(error)
        reason = "代理或上游错误，未收到响应"
        if detail:
            reason = f"{reason}：{detail}"
        return "error", reason[:240]
    return "partial", RESPONSE_MISSING_REASON


def _body_is_legitimately_empty(method: str, status: int) -> bool:
    if str(method or "").upper() == "HEAD":
        return True
    return int(status or 0) in (204, 304)
