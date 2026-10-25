"""Detection-only observation of traffic the local HTTP proxy cannot see.

EgressScope never redirects traffic, never installs a kernel driver, and never
decrypts QUIC. This module only reads the local connection table and, on
Windows, the local DNS resolver cache. Every event is a candidate or metadata,
not proof that content was sent outside the proxy.
"""
from __future__ import annotations

import ipaddress
import json
import logging
import os
import socket
import subprocess
import sys
import threading
import time
from datetime import datetime
from typing import Any, Iterable

log = logging.getLogger(__name__)

SCAN_INTERVAL = 15.0
DEDUPE_SECONDS = 600.0
DNS_REFRESH_SECONDS = 60.0
MAX_EVENTS_PER_SCAN = 50
MAX_EVENTS_PER_DAY = 5000
DNS_CACHE_LIMIT = 5000
DNS_TIMEOUT = 8.0

DIRECT_PORTS = {80, 443, 8080, 8443}
DNS_TCP_PORTS = {53, 853}

NOTE_QUIC = "QUIC/UDP 443 候选：本地 HTTP 代理不覆盖，无法解密"
NOTE_DNS = "仅记录 DNS 目标，不记录查询内容"
NOTE_DIRECT = "直连候选：可能是未遵循系统代理的应用，也可能是上游代理或非 HTTP 协议"
STATUS_NOTE = (
    "只观测本机连接表与 DNS 解析缓存，不做内核级透明重定向；"
    "QUIC 与端到端加密内容不可见"
)

_KIND_CONFIDENCE = {
    "quic": "candidate",
    "dns": "metadata",
    "direct_tcp": "candidate",
}


def classify_destination(protocol: str, port: int) -> tuple[str, str]:
    """Classify one remote endpoint, or return ``("", "")`` to ignore it."""
    protocol = str(protocol or "").lower()
    try:
        port = int(port)
    except (TypeError, ValueError):
        return "", ""
    if port <= 0:
        return "", ""
    if protocol == "udp" and port == 443:
        return "quic", NOTE_QUIC
    if (protocol in ("tcp", "udp") and port == 53) or (protocol == "tcp" and port == 853):
        return "dns", NOTE_DNS
    if protocol == "tcp" and port in DIRECT_PORTS:
        return "direct_tcp", NOTE_DIRECT
    return "", ""


def is_public_remote(value: str) -> bool:
    """True only for globally routable addresses (no loopback/private/reserved)."""
    try:
        raw = str(value or "").split("%", 1)[0]
        address = ipaddress.ip_address(raw)
    except ValueError:
        return False
    if (
        address.is_loopback
        or address.is_private
        or address.is_link_local
        or address.is_multicast
        or address.is_reserved
        or address.is_unspecified
    ):
        return False
    return bool(address.is_global)


def parse_dns_cache(payload: Any) -> dict[str, str]:
    """Parse ``Get-DnsClientCache | Select Entry,Data`` JSON into IP -> name."""
    if isinstance(payload, (bytes, bytearray)):
        try:
            payload = bytes(payload).decode("utf-8", "replace")
        except Exception:
            return {}
    if isinstance(payload, str):
        try:
            payload = json.loads(payload)
        except (TypeError, ValueError):
            return {}
    if isinstance(payload, dict):
        entries: Iterable[Any] = [payload]
    elif isinstance(payload, list):
        entries = payload
    else:
        return {}
    mapping: dict[str, str] = {}
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        name = str(entry.get("Entry") or "").strip()
        data = entry.get("Data")
        values = data if isinstance(data, list) else [data]
        for value in values:
            if not isinstance(value, str):
                continue
            ip = value.strip().split("%", 1)[0]
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                continue
            if ip and ip not in mapping:
                mapping[ip] = name
                if len(mapping) >= DNS_CACHE_LIMIT:
                    return mapping
    return mapping


def _protocol_name(value: Any) -> str:
    if isinstance(value, str):
        low = value.lower()
        if low in ("tcp", "udp"):
            return low
    try:
        if int(value) == socket.SOCK_STREAM:
            return "tcp"
        if int(value) == socket.SOCK_DGRAM:
            return "udp"
    except (TypeError, ValueError):
        pass
    return ""


def _remote_tuple(connection: Any) -> tuple[str, int]:
    raddr = getattr(connection, "raddr", None)
    if not raddr:
        return "", 0
    try:
        ip = str(raddr[0] or "")
        port = int(raddr[1] or 0)
    except (TypeError, ValueError, IndexError):
        return "", 0
    return ip, port


def _local_midnight() -> float:
    return datetime.now().replace(hour=0, minute=0, second=0, microsecond=0).timestamp()


class NetworkWatch:
    def __init__(self, app=None) -> None:
        self.app = app
        self.interval = SCAN_INTERVAL
        self.running = False
        self.last_scan_at = 0.0
        self.last_error = ""
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._lock = threading.RLock()
        self._seen: dict[tuple[Any, ...], float] = {}
        self._dns_map: dict[str, str] = {}
        self._dns = {
            "supported": sys.platform == "win32",
            "cached": 0,
            "last_at": 0.0,
            "error": "",
        }
        self._dns_next_at = 0.0

    # ---------- lifecycle ----------
    def _enabled(self) -> bool:
        if self.app is None:
            return True
        settings = getattr(self.app, "settings", None)
        if settings is None:
            return True
        return bool(getattr(settings, "network_watch_enabled", True))

    def _capture_enabled(self) -> bool:
        settings = getattr(self.app, "settings", None) if self.app is not None else None
        return bool(getattr(settings, "capture_enabled", True))

    def _active(self) -> bool:
        return self._enabled() and self._capture_enabled()

    def start(self) -> bool:
        if not self._active():
            return False
        with self._lock:
            if self._thread and self._thread.is_alive():
                self.running = True
                return True
            self._stop.clear()
            self.running = True
            self._thread = threading.Thread(target=self._loop, name="egressscope-netwatch", daemon=True)
            self._thread.start()
            log.info("network watch started (interval %.0fs)", self.interval)
            return True

    def stop(self) -> None:
        self._stop.set()
        thread = self._thread
        if thread and thread.is_alive():
            thread.join(timeout=5)
        self._thread = None
        self.running = False

    def _loop(self) -> None:
        # Delay the first scan so startup is not blocked by process enumeration.
        while not self._stop.wait(self.interval):
            if not self._active():
                continue
            try:
                self.scan_once()
            except Exception:
                self.last_error = "扫描异常"
                log.exception("network watch scan failed")
        if self._thread is threading.current_thread():
            self.running = False

    # ---------- scanning ----------
    def scan_once(
        self,
        connections: list[Any] | None = None,
        dns_map: dict[str, str] | None = None,
        now: float | None = None,
    ) -> dict[str, Any]:
        now = float(now or time.time())
        if self.app is not None and not self._active():
            self.last_scan_at = now
            return {"candidates": 0, "stored": 0, "skipped": True, "error": ""}
        if connections is None:
            try:
                import psutil

                connections = list(psutil.net_connections(kind="inet"))
            except ImportError:
                self.last_error = "psutil 不可用"
                self.last_scan_at = now
                return {"candidates": 0, "stored": 0, "error": self.last_error}
            except (psutil.AccessDenied, OSError) as exc:
                self.last_error = f"读取连接表失败：{type(exc).__name__}"
                self.last_scan_at = now
                return {"candidates": 0, "stored": 0, "error": self.last_error}
        if dns_map is None:
            dns_map = self._maybe_refresh_dns(now)
        else:
            self._dns["cached"] = len(dns_map)
        store = getattr(self.app, "store", None) if self.app is not None else None
        resolver = getattr(self.app, "resolver", None) if self.app is not None else None
        own_pid = os.getpid()
        reserved_ports = self._self_ports()
        today = _local_midnight()
        stored_today = 0
        if store is not None:
            try:
                stored_today = int(store.net_event_counts(since=today).get("total", 0))
            except Exception:
                stored_today = 0
        candidates = 0
        stored = 0
        info_cache: dict[int | None, Any] = {}
        for connection in connections:
            if self._stop.is_set() or not self._active():
                break
            if candidates >= MAX_EVENTS_PER_SCAN or stored_today + stored >= MAX_EVENTS_PER_DAY:
                break
            try:
                pid = getattr(connection, "pid", None)
                if pid is not None:
                    pid = int(pid)
            except (TypeError, ValueError):
                pid = None
            if pid is not None and pid == own_pid:
                continue
            ip, port = _remote_tuple(connection)
            if not ip or not port or port in reserved_ports:
                continue
            if not is_public_remote(ip):
                continue
            protocol = _protocol_name(getattr(connection, "type", None))
            if not protocol:
                continue
            kind, note = classify_destination(protocol, port)
            if not kind:
                continue
            candidates += 1
            domain = str((dns_map or {}).get(ip) or "")
            key = (kind, pid, ip, port, domain)
            if not self._remember(key, now):
                continue
            info = None
            if pid is not None and resolver is not None:
                if pid not in info_cache:
                    try:
                        info_cache[pid] = resolver.info_for_pid(pid)
                    except Exception:
                        info_cache[pid] = None
                info = info_cache.get(pid)
            record = {
                "ts": now,
                "kind": kind,
                "pid": pid,
                "proc_name": getattr(info, "name", "") if info else "",
                "proc_path": getattr(info, "exe", "") if info else "",
                "app_kind": getattr(info, "app_kind", "") if info else "",
                "remote_ip": ip,
                "remote_port": port,
                "protocol": protocol,
                "domain": domain,
                "confidence": _KIND_CONFIDENCE.get(kind, "candidate"),
                "note": note,
                "seen_count": 1,
            }
            if store is not None:
                try:
                    store.add_net_event(record)
                except Exception:
                    log.debug("network event store failed", exc_info=True)
                    continue
            stored += 1
        self.last_scan_at = now
        self.last_error = ""
        return {"candidates": candidates, "stored": stored, "error": ""}

    def _self_ports(self) -> set[int]:
        ports: set[int] = set()
        if self.app is None:
            return ports
        for attr in ("listen_port", "web_port"):
            try:
                value = int(getattr(self.app, attr, 0) or 0)
            except (TypeError, ValueError):
                value = 0
            if value:
                ports.add(value)
        settings = getattr(self.app, "settings", None)
        for attr in ("listen_port", "web_port"):
            try:
                value = int(getattr(settings, attr, 0) or 0)
            except (TypeError, ValueError):
                value = 0
            if value:
                ports.add(value)
        return ports

    def _remember(self, key: tuple[Any, ...], now: float) -> bool:
        with self._lock:
            previous = self._seen.get(key)
            if previous is not None and now - previous < DEDUPE_SECONDS:
                return False
            self._seen[key] = now
            if len(self._seen) > 4096:
                cutoff = now - DEDUPE_SECONDS
                self._seen = {k: ts for k, ts in self._seen.items() if ts > cutoff}
            return True

    # ---------- DNS cache ----------
    def _maybe_refresh_dns(self, now: float) -> dict[str, str]:
        if sys.platform != "win32":
            self._dns["supported"] = False
            return self._dns_map
        if now < self._dns_next_at and (self._dns["last_at"] or self._dns["error"]):
            return self._dns_map
        self._dns_next_at = now + DNS_REFRESH_SECONDS
        mapping = self._read_dns_cache()
        if mapping is not None:
            self._dns_map = mapping
            self._dns["cached"] = len(mapping)
            self._dns["last_at"] = now
            self._dns["error"] = ""
        return self._dns_map

    def _read_dns_cache(self) -> dict[str, str] | None:
        command = (
            "$OutputEncoding=[Console]::OutputEncoding=[Text.Encoding]::UTF8; "
            "Get-DnsClientCache | Select-Object Entry,Data | "
            "ConvertTo-Json -Compress -Depth 3"
        )
        creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        try:
            completed = subprocess.run(
                ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", command],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=DNS_TIMEOUT,
                creationflags=creationflags,
                check=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            self._dns["error"] = f"DNS 缓存读取失败：{type(exc).__name__}"
            return None
        if completed.returncode != 0:
            self._dns["error"] = f"DNS 缓存读取失败：PowerShell 退出码 {completed.returncode}"
            return None
        try:
            mapping = parse_dns_cache(completed.stdout or "")
        except Exception:
            self._dns["error"] = "DNS 缓存解析失败"
            return None
        return mapping

    # ---------- status ----------
    def status(self) -> dict[str, Any]:
        counts = {"direct_tcp": 0, "quic": 0, "dns": 0, "total": 0}
        store = getattr(self.app, "store", None) if self.app is not None else None
        if store is not None:
            try:
                counts = store.net_event_counts(since=_local_midnight())
            except Exception:
                pass
        dns = {
            "supported": bool(self._dns.get("supported")),
            "cached": int(self._dns.get("cached") or 0),
            "last_at": float(self._dns.get("last_at") or 0.0),
            "error": str(self._dns.get("error") or ""),
        }
        return {
            "supported": True,
            "enabled": self._enabled(),
            "paused": not self._capture_enabled(),
            "running": bool(self.running),
            "interval": self.interval,
            "last_scan_at": self.last_scan_at,
            "last_error": self.last_error,
            "counts": counts,
            "dns": dns,
            "note": STATUS_NOTE,
        }

    def snapshot(self, limit: int = 50) -> dict[str, Any]:
        limit = max(1, min(200, int(limit or 50)))
        payload = self.status()
        payload["events"] = self.recent_events(limit)
        payload["limit"] = limit
        return payload

    def recent_events(self, limit: int = 50) -> list[dict[str, Any]]:
        store = getattr(self.app, "store", None) if self.app is not None else None
        if store is None:
            return []
        try:
            return store.list_net_events(limit=limit)
        except Exception:
            log.debug("network event read failed", exc_info=True)
            return []
