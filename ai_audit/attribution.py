from __future__ import annotations

import logging
import re
import threading
import time
from dataclasses import dataclass, field
from typing import Any

import psutil

log = logging.getLogger(__name__)

_SECRET_IN_CMDLINE = re.compile(r"(sk-[A-Za-z0-9_\-]{8,}|gh[pousr]_[A-Za-z0-9]{8,}|AIza[0-9A-Za-z_\-]{8,})")
_ASSIGNMENT = re.compile(r"(?i)((?:key|token|secret|password|credential)[^=\s]*=)(\S+)")

APP_FINGERPRINTS: list[tuple[tuple[str, ...], str, str]] = [
    (("claude",), "Claude Code / Claude Desktop", "agent"),
    (("codex",), "OpenAI Codex CLI", "agent"),
    (("gemini", "gemini-cli"), "Gemini CLI", "agent"),
    (("aider",), "Aider", "agent"),
    (("openhands",), "OpenHands", "agent"),
    (("goose",), "Goose", "agent"),
    (("cursor",), "Cursor", "editor"),
    (("qoder",), "Qoder", "editor"),
    (("windsurf",), "Windsurf", "editor"),
    (("code.exe", "visual studio code"), "VS Code", "editor"),
    (("devenv.exe",), "Visual Studio", "editor"),
    (("idea64.exe", "pycharm64.exe", "webstorm64.exe", "goland64.exe"), "JetBrains IDE", "editor"),
    (("chatgpt",), "ChatGPT Desktop", "agent"),
    (("ollama",), "Ollama", "local_model"),
    (("lm studio", "lmstudio"), "LM Studio", "local_model"),
    (("localai",), "LocalAI", "local_model"),
    (("jan.exe",), "Jan", "local_model"),
    (("chrome.exe",), "Chrome", "browser"),
    (("msedge.exe",), "Edge", "browser"),
    (("firefox.exe",), "Firefox", "browser"),
    (("python.exe", "pythonw.exe"), "Python", "runtime"),
    (("node.exe",), "Node.js", "runtime"),
    (("bun.exe",), "Bun", "runtime"),
    (("deno.exe",), "Deno", "runtime"),
    (("java.exe", "javaw.exe"), "Java", "runtime"),
    (("go.exe", "myapp.exe"), "Go app", "runtime"),
    (("powershell.exe", "pwsh.exe", "cmd.exe", "wsl.exe", "bash.exe"), "Shell", "runtime"),
    (("svchost.exe", "services.exe", "lsass.exe", "winlogon.exe"), "Windows service", "system"),
]

_AGENT_HINTS = (
    "langchain",
    "llama-index",
    "autogen",
    "crewai",
    "openai",
    "anthropic",
    "litellm",
    "mcp",
    "modelcontextprotocol",
    "transformers",
    "vllm",
    "ollama",
)

_EDITOR_PARENTS = ("cursor.exe", "code.exe", "qoder.exe", "windsurf.exe", "devenv.exe", "idea64.exe")


@dataclass
class ProcessInfo:
    pid: int
    name: str = ""
    exe: str = ""
    ppid: int | None = None
    username: str = ""
    create_time: float | None = None
    cmdline: str = ""
    app_chain: list[dict[str, Any]] = field(default_factory=list)
    app_kind: str = ""
    family: str = ""

    def as_record(self) -> dict[str, Any]:
        return {
            "pid": self.pid,
            "proc_name": self.name,
            "proc_path": self.exe,
            "ppid": self.ppid,
            "proc_user": self.username,
            "proc_create_time": self.create_time,
            "cmdline": self.cmdline,
            "app_chain": self.app_chain,
            "app_kind": self.app_kind,
        }


class ProcessResolver:
    """Map a proxied client socket to the owning process using the OS TCP table."""

    def __init__(self, proxy_port: int) -> None:
        self.proxy_port = proxy_port
        self._lock = threading.RLock()
        self._table_ts = 0.0
        self._port_map: dict[int, int] = {}
        self._info_cache: dict[tuple[int, float | None], tuple[float, ProcessInfo | None]] = {}
        self._last_good: dict[int, tuple[float, int]] = {}
        self.last_error = ""

    def set_proxy_port(self, port: int) -> None:
        self.proxy_port = port
        self.invalidate()

    def invalidate(self) -> None:
        with self._lock:
            self._table_ts = 0.0
            self._port_map.clear()

    def _refresh_table(self) -> None:
        now = time.time()
        with self._lock:
            if now - self._table_ts < 1.0:
                return
            try:
                connections = psutil.net_connections(kind="tcp")
            except (psutil.AccessDenied, OSError) as exc:
                self.last_error = f"TCP table unavailable: {exc}"
                self._table_ts = now
                return
            port_map: dict[int, int] = {}
            for conn in connections:
                if not conn.pid or not conn.laddr:
                    continue
                lport = getattr(conn.laddr, "port", None)
                rport = getattr(conn.raddr, "port", None) if conn.raddr else None
                if lport is None:
                    continue
                if rport == self.proxy_port or conn.status in (psutil.CONN_ESTABLISHED, psutil.CONN_SYN_SENT):
                    port_map[int(lport)] = int(conn.pid)
            self._port_map = port_map
            self._table_ts = now
            if connections:
                self.last_error = ""

    def resolve(self, client_ip: str, client_port: int | None) -> ProcessInfo | None:
        if not client_port:
            return None
        if client_ip not in ("127.0.0.1", "::1", "localhost"):
            return None
        self._refresh_table()
        with self._lock:
            pid = self._port_map.get(int(client_port))
            if pid is None:
                recent = self._last_good.get(int(client_port))
                if recent and time.time() - recent[0] < 20:
                    pid = recent[1]
            if pid is None:
                return None
            self._last_good[int(client_port)] = (time.time(), pid)
        return self.info_for_pid(pid)

    def info_for_pid(self, pid: int) -> ProcessInfo | None:
        try:
            proc = psutil.Process(pid)
            create_time = proc.create_time()
        except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
            return None
        key = (pid, create_time)
        now = time.time()
        with self._lock:
            cached = self._info_cache.get(key)
            if cached and now - cached[0] < 30:
                return cached[1]
        info = self._build_info(proc, create_time)
        with self._lock:
            self._info_cache[key] = (now, info)
            for old_key in [k for k in self._info_cache if now - self._info_cache[k][0] > 120]:
                self._info_cache.pop(old_key, None)
        return info

    def _build_info(self, proc: psutil.Process, create_time: float) -> ProcessInfo:
        info = ProcessInfo(pid=proc.pid, create_time=create_time)
        try:
            info.name = proc.name()
        except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
            return info
        try:
            info.exe = proc.exe()
        except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
            info.exe = ""
        try:
            info.username = proc.username()
        except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
            pass
        try:
            info.ppid = proc.ppid()
        except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
            pass
        try:
            raw_cmdline = " ".join(proc.cmdline())[:600]
            info.cmdline = _sanitize_cmdline(raw_cmdline)
        except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
            info.cmdline = ""

        chain: list[dict[str, Any]] = []
        cursor = proc
        for _ in range(4):
            try:
                parent = cursor.parent()
            except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
                break
            if not parent:
                break
            try:
                chain.append({"pid": parent.pid, "name": parent.name()})
            except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
                break
            cursor = parent
        info.app_chain = chain
        info.family, info.app_kind = _classify(info, chain)
        return info


def _classify(info: ProcessInfo, chain: list[dict[str, Any]]) -> tuple[str, str]:
    haystack = " ".join([info.name, info.exe, info.cmdline, *[c.get("name", "") for c in chain]]).lower()
    for needles, label, family in APP_FINGERPRINTS:
        if any(needle in haystack for needle in needles):
            if family == "editor" and "helper" in info.name.lower():
                return "editor", label
            return family, label
    parent_names = [str(c.get("name", "")).lower() for c in chain]
    if any(name in _EDITOR_PARENTS for name in parent_names):
        return "editor", "编辑器子进程"
    if info.name.lower() in ("python.exe", "pythonw.exe", "node.exe", "bun.exe") and any(
        hint in info.cmdline.lower() for hint in _AGENT_HINTS
    ):
        return "agent", "AI 脚本 / SDK"
    if any(hint in haystack for hint in _AGENT_HINTS):
        return "agent", "AI 工具进程"
    return "other", "其他进程"


def _sanitize_cmdline(value: str) -> str:
    value = _SECRET_IN_CMDLINE.sub("[REDACTED]", value)
    value = _ASSIGNMENT.sub(lambda m: m.group(1) + "[REDACTED]", value)
    return value[:280]
