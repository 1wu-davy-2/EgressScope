from __future__ import annotations

import os
import sys
from pathlib import Path


def is_frozen() -> bool:
    return bool(getattr(sys, "frozen", False))


def resource_dir() -> Path:
    """Directory containing the bundled web assets."""
    if is_frozen():
        return Path(getattr(sys, "_MEIPASS")) / "web"
    return Path(__file__).resolve().parent.parent / "web"


def default_home() -> Path:
    override = os.environ.get("EGRESSSCOPE_HOME")
    if override:
        return Path(os.path.expandvars(override)).expanduser()
    local = os.environ.get("LOCALAPPDATA")
    if local:
        return Path(local) / "EgressScope"
    return Path.home() / ".egressscope"


class AppPaths:
    def __init__(self, home: Path | str | None = None) -> None:
        self.home = Path(home).expanduser().resolve() if home else default_home().resolve()
        self.data = self.home / "data"
        self.certs = self.data / "certs"
        self.exports = self.data / "exports"
        self.canaries = self.home / "canaries"
        self.logs = self.data / "logs"
        self.db = self.data / "egress.db"
        self.config = self.data / "config.json"
        self.secret = self.data / "secret.bin"
        self.proxy_backup = self.data / "proxy-backup.json"
        self.ca_pem = self.certs / "mitmproxy-ca.pem"
        self.ca_cert_pem = self.certs / "mitmproxy-ca-cert.pem"
        self.ca_cert_cer = self.certs / "mitmproxy-ca-cert.cer"

    def ensure(self) -> None:
        for path in (self.home, self.data, self.certs, self.exports, self.logs):
            path.mkdir(parents=True, exist_ok=True)

    @property
    def agent_env_file(self) -> Path:
        return self.data / "agent-env.cmd"
