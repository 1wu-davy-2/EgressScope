from __future__ import annotations

import hashlib
import json
import os
import threading
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit


def _default_watch_paths() -> list[str]:
    home = Path.home()
    candidates = [
        home / "Documents",
        home / "Desktop",
        home / "Downloads",
        home / ".ssh",
        home / ".aws",
    ]
    return [str(p) for p in candidates if p.exists()]


@dataclass
class Settings:
    listen_host: str = "127.0.0.1"
    listen_port: int = 8899
    web_port: int = 8898
    capture_enabled: bool = True
    blocking_enabled: bool = False
    block_risk: int = 85
    store_bodies: bool = True
    body_limit_bytes: int = 2_000_000
    stream_threshold: str = "3m"
    retention_days: int = 7
    file_guard_enabled: bool = True
    file_guard_interval: float = 4.0
    canary_enabled: bool = False
    canary_dir: str = ""
    watch_paths: list[str] = field(default_factory=_default_watch_paths)
    insecure_upstream: bool = False
    upstream_ca: str = ""
    upstream_proxy: str = ""
    inherit_system_proxy: bool = True
    autostart_enabled: bool = True
    update_check_enabled: bool = True
    network_watch_enabled: bool = True
    onboarded: bool = False

    def normalized(self) -> "Settings":
        self.listen_host = "127.0.0.1"
        self.listen_port = _clamp_int(self.listen_port, 1024, 65535, 8899)
        self.web_port = _clamp_int(self.web_port, 1024, 65535, 8898)
        self.block_risk = _clamp_int(self.block_risk, 1, 100, 85)
        self.body_limit_bytes = _clamp_int(self.body_limit_bytes, 64_000, 50_000_000, 2_000_000)
        self.retention_days = _clamp_int(self.retention_days, 1, 365, 7)
        self.file_guard_interval = min(120.0, max(1.0, float(self.file_guard_interval or 4.0)))
        self.watch_paths = [str(Path(os.path.expandvars(p)).expanduser()) for p in self.watch_paths if p.strip()]
        self.canary_dir = str(Path(os.path.expandvars(self.canary_dir)).expanduser()) if self.canary_dir else ""
        self.stream_threshold = str(self.stream_threshold or "3m")
        self.upstream_ca = str(self.upstream_ca or "")
        self.upstream_proxy = _normalize_proxy_url(self.upstream_proxy)
        self.inherit_system_proxy = bool(self.inherit_system_proxy)
        return self

    def public_dict(self) -> dict[str, Any]:
        return asdict(self)


def _clamp_int(value: Any, low: int, high: int, default: int) -> int:
    try:
        return min(high, max(low, int(value)))
    except (TypeError, ValueError):
        return default


def _normalize_proxy_url(value: Any) -> str:
    raw = str(value or "").strip()
    if not raw:
        return ""
    if "://" not in raw:
        raw = "http://" + raw
    try:
        parts = urlsplit(raw)
        port = parts.port
    except ValueError:
        return ""
    scheme = parts.scheme.lower()
    if scheme not in ("http", "https") or not parts.hostname:
        return ""
    if parts.username or parts.password or parts.path not in ("", "/") or parts.query or parts.fragment:
        return ""
    host = parts.hostname
    if ":" in host:
        host = f"[{host}]"
    return f"{scheme}://{host}:{port or (443 if scheme == 'https' else 80)}"


EDITABLE_KEYS = {
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
    "update_check_enabled",
    "network_watch_enabled",
    "onboarded",
}


class ConfigStore:
    def __init__(self, path: Path) -> None:
        self.path = path
        self._lock = threading.RLock()
        self.settings = self._load()
        self._digest = self._current_digest()
        self.reload_error = ""

    def _current_digest(self) -> str:
        try:
            return hashlib.sha256(self.path.read_bytes()).hexdigest()
        except OSError:
            return ""

    @staticmethod
    def _parse(raw: bytes) -> Settings:
        payload = json.loads(raw.decode("utf-8"))
        if not isinstance(payload, dict):
            raise ValueError("config root must be a JSON object")
        known = {f for f in Settings.__dataclass_fields__}
        values = {k: v for k, v in payload.items() if k in known}
        return Settings(**values).normalized()

    def _load(self) -> Settings:
        if not self.path.exists():
            return Settings().normalized()
        try:
            return self._parse(self.path.read_bytes())
        except (OSError, ValueError, TypeError):
            return Settings().normalized()

    def save(self) -> None:
        with self._lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix(".tmp")
            payload = json.dumps(self.settings.public_dict(), indent=2, ensure_ascii=False).encode("utf-8")
            tmp.write_bytes(payload)
            os.replace(tmp, self.path)
            self._digest = hashlib.sha256(payload).hexdigest()

    def reload_if_changed(self) -> list[str]:
        """Adopt edits made to the config file outside the running process."""
        with self._lock:
            try:
                raw = self.path.read_bytes()
            except OSError:
                if not self._digest:
                    return []
                self._digest = ""
                self.reload_error = "config file is missing or unreadable; keeping current settings"
                return []
            digest = hashlib.sha256(raw).hexdigest()
            if digest == self._digest:
                return []
            try:
                fresh = self._parse(raw)
            except (ValueError, TypeError) as exc:
                self._digest = digest
                self.reload_error = f"config file rejected; keeping current settings ({exc})"
                return []
            self._digest = digest
            self.reload_error = ""
            changed = [
                key
                for key in Settings.__dataclass_fields__
                if key in EDITABLE_KEYS and getattr(fresh, key) != getattr(self.settings, key)
            ]
            for key in changed:
                setattr(self.settings, key, getattr(fresh, key))
            self.settings.normalized()
            return changed

    def update(self, patch: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            for key, value in patch.items():
                if key not in EDITABLE_KEYS:
                    continue
                setattr(self.settings, key, value)
            self.settings.normalized()
            self.save()
            return self.settings.public_dict()
