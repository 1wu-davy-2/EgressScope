from __future__ import annotations

import ctypes
import ipaddress
import json
import os
import shlex
import socket
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from cryptography import x509
from cryptography.hazmat.primitives import hashes

from .paths import AppPaths

CREATE_NO_WINDOW = 0x08000000 if sys.platform == "win32" else 0
INTERNET_SETTINGS = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
CA_CN = "EgressScope Local Audit CA"


class SystemControlError(RuntimeError):
    pass


def ensure_ca(cert_dir: Path) -> dict[str, Any]:
    cert_dir.mkdir(parents=True, exist_ok=True)
    ca_file = cert_dir / "mitmproxy-ca.pem"
    cert_file = cert_dir / "mitmproxy-ca-cert.pem"
    if not ca_file.exists():
        from mitmproxy import certs

        certs.CertStore.create_store(
            path=cert_dir,
            basename="mitmproxy",
            key_size=2048,
            organization="EgressScope",
            cn=CA_CN,
        )
    if not cert_file.exists():
        raise SystemControlError(f"CA certificate missing: {cert_file}")
    try:
        os.chmod(ca_file, 0o600)
    except OSError:
        pass
    return ca_info(cert_file)


def ca_info(cert_path: Path) -> dict[str, Any]:
    if not cert_path.exists():
        return {"exists": False, "path": str(cert_path)}
    cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
    cn = ""
    for attr in cert.subject:
        if attr.oid == x509.NameOID.COMMON_NAME:
            cn = attr.value
            break
    try:
        expires = cert.not_valid_after_utc
    except AttributeError:
        expires = cert.not_valid_after.replace(tzinfo=timezone.utc)
    return {
        "exists": True,
        "path": str(cert_path),
        "common_name": cn,
        "organization": "EgressScope",
        "sha1": cert.fingerprint(hashes.SHA1()).hex().upper(),
        "sha256": cert.fingerprint(hashes.SHA256()).hex().upper(),
        "expires_at": expires.isoformat(),
        "expired": expires < datetime.now(timezone.utc),
    }


def is_ca_installed(thumbprint: str) -> bool:
    if sys.platform != "win32" or not thumbprint:
        return False
    command = (
        f"(Get-ChildItem Cert:\\CurrentUser\\Root | "
        f"Where-Object {{$_.Thumbprint -eq '{thumbprint}'}} | Measure-Object).Count"
    )
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", command],
            capture_output=True,
            text=True,
            timeout=25,
            creationflags=CREATE_NO_WINDOW,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return result.returncode == 0 and result.stdout.strip().endswith("1")


def install_ca(cert_path: Path) -> dict[str, Any]:
    if sys.platform != "win32":
        raise SystemControlError("CA installation is only supported on Windows")
    if not cert_path.exists():
        raise SystemControlError("CA certificate not found")
    result = subprocess.run(
        ["certutil", "-user", "-addstore", "-f", "Root", str(cert_path)],
        capture_output=True,
        text=True,
        errors="replace",
        timeout=120,
        creationflags=CREATE_NO_WINDOW,
    )
    info = ca_info(cert_path)
    return {
        "ok": result.returncode == 0,
        "returncode": result.returncode,
        "message": (result.stdout or result.stderr or "").strip()[-800:],
        "installed": is_ca_installed(info.get("sha1", "")),
        "ca": info,
    }


def remove_ca(thumbprint: str) -> dict[str, Any]:
    if sys.platform != "win32":
        raise SystemControlError("CA removal is only supported on Windows")
    if not thumbprint or any(c not in "0123456789ABCDEF" for c in thumbprint.upper()):
        raise SystemControlError("Invalid certificate thumbprint")
    command = (
        f"Get-ChildItem Cert:\\CurrentUser\\Root | "
        f"Where-Object {{$_.Thumbprint -eq '{thumbprint}'}} | Remove-Item -Force"
    )
    result = subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", command],
        capture_output=True,
        text=True,
        errors="replace",
        timeout=60,
        creationflags=CREATE_NO_WINDOW,
    )
    return {
        "ok": result.returncode == 0,
        "installed": is_ca_installed(thumbprint),
        "message": (result.stdout or result.stderr or "").strip()[-800:],
    }


def _open_internet_settings():
    import winreg

    return winreg.OpenKey(winreg.HKEY_CURRENT_USER, INTERNET_SETTINGS, 0, winreg.KEY_READ | winreg.KEY_WRITE)


def _read_values() -> dict[str, Any]:
    import winreg

    values: dict[str, Any] = {}
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, INTERNET_SETTINGS, 0, winreg.KEY_READ) as key:
        for name in ("ProxyEnable", "ProxyServer", "ProxyOverride", "AutoConfigURL"):
            try:
                values[name] = winreg.QueryValueEx(key, name)[0]
            except FileNotFoundError:
                values[name] = None
    return values


def _notify_settings_changed() -> bool:
    if sys.platform != "win32":
        return False
    try:
        wininet = ctypes.windll.wininet
        ok1 = wininet.InternetSetOptionW(None, 39, None, 0)  # INTERNET_OPTION_SETTINGS_CHANGED
        ok2 = wininet.InternetSetOptionW(None, 37, None, 0)  # INTERNET_OPTION_REFRESH
        return bool(ok1 and ok2)
    except OSError:
        return False


def proxy_state(expected_port: int | None = None) -> dict[str, Any]:
    if sys.platform != "win32":
        return {
            "available": False,
            "error": "System proxy control is only supported on Windows",
            "enabled": False,
            "server": "",
            "override": "",
            "auto_config_url": "",
            "ours": False,
            "pac_active": False,
        }
    try:
        values = _read_values()
    except OSError as exc:
        return {"available": False, "error": str(exc), "enabled": False, "ours": False}
    server = str(values.get("ProxyServer") or "")
    ours = False
    if expected_port:
        ours = f"127.0.0.1:{expected_port}" in server or f"localhost:{expected_port}" in server
    return {
        "available": True,
        "enabled": bool(values.get("ProxyEnable")),
        "server": server,
        "override": str(values.get("ProxyOverride") or ""),
        "auto_config_url": str(values.get("AutoConfigURL") or ""),
        "ours": bool(values.get("ProxyEnable")) and ours,
        "pac_active": bool(values.get("AutoConfigURL")),
    }


def detect_loopback_proxy(exclude_ports: set[int] | None = None) -> str:
    """Return the active, non-PAC system HTTP proxy when it is a local loopback proxy."""
    state = proxy_state()
    if not state.get("available") or not state.get("enabled") or state.get("pac_active"):
        return ""
    raw = str(state.get("server") or "").strip()
    if not raw:
        return ""
    candidates: list[tuple[str, str]] = []
    if "=" in raw:
        for part in raw.split(";"):
            if "=" not in part:
                continue
            scheme, addr = part.split("=", 1)
            scheme = scheme.strip().lower()
            if scheme in ("http", "https") and addr.strip():
                candidates.append((scheme, addr.strip()))
    else:
        candidates.append(("http", raw))
    excluded = set(exclude_ports or ())
    for scheme, addr in candidates:
        try:
            if "://" in addr:
                parsed = urlsplit(addr)
                scheme = parsed.scheme.lower()
            else:
                parsed = urlsplit("//" + addr)
            port = parsed.port
        except ValueError:
            continue
        host = parsed.hostname
        if scheme not in ("http", "https") or not host or not port or port in excluded:
            continue
        if host.lower() != "localhost":
            try:
                if not ipaddress.ip_address(host).is_loopback:
                    continue
            except ValueError:
                continue
        host_text = f"[{host}]" if ":" in host else host
        return f"{scheme}://{host_text}:{port}"
    return ""


def enable_system_proxy(paths: AppPaths, port: int) -> dict[str, Any]:
    if sys.platform != "win32":
        raise SystemControlError("System proxy control is only supported on Windows")
    values = _read_values()
    pac = str(values.get("AutoConfigURL") or "").strip()
    if pac:
        raise SystemControlError(
            "检测到 PAC 自动配置脚本（AutoConfigURL）。静态代理不会生效，请先在 Windows 设置中关闭自动配置，再启用 EgressScope 代理。"
        )
    backup = load_proxy_backup(paths)
    if not backup:
        backup = {
            "created_at": time.time(),
            "managed": True,
            "host": "127.0.0.1",
            "port": port,
            "values": values,
        }
        tmp = paths.proxy_backup.with_suffix(".tmp")
        tmp.write_text(json.dumps(backup, indent=2, ensure_ascii=False), encoding="utf-8")
        os.replace(tmp, paths.proxy_backup)
    override_parts = [p.strip() for p in str(values.get("ProxyOverride") or "").split(";") if p.strip()]
    for token in ("localhost", "127.0.0.1", "<local>"):
        if token not in override_parts:
            override_parts.append(token)
    import winreg

    with _open_internet_settings() as key:
        winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 1)
        winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, f"127.0.0.1:{port}")
        winreg.SetValueEx(key, "ProxyOverride", 0, winreg.REG_SZ, ";".join(override_parts))
    notified = _notify_settings_changed()
    return {
        "ok": True,
        "notified": notified,
        "port": port,
        "backup": str(paths.proxy_backup),
        "state": proxy_state(port),
    }


def restore_system_proxy(paths: AppPaths) -> dict[str, Any]:
    if sys.platform != "win32":
        raise SystemControlError("System proxy control is only supported on Windows")
    backup = load_proxy_backup(paths)
    if not backup:
        raise SystemControlError("没有找到 EgressScope 创建的系统代理备份，未修改系统设置")
    original = backup.get("values") or {}
    import winreg

    with _open_internet_settings() as key:
        for name in ("ProxyEnable", "ProxyServer", "ProxyOverride", "AutoConfigURL"):
            value = original.get(name)
            try:
                if value is None:
                    winreg.DeleteValue(key, name)
                elif name == "ProxyEnable":
                    winreg.SetValueEx(key, name, 0, winreg.REG_DWORD, int(value))
                else:
                    winreg.SetValueEx(key, name, 0, winreg.REG_SZ, str(value))
            except FileNotFoundError:
                pass
    notified = _notify_settings_changed()
    paths.proxy_backup.unlink(missing_ok=True)
    return {"ok": True, "notified": notified, "state": proxy_state(), "restored_at": time.time()}


def load_proxy_backup(paths: AppPaths) -> dict[str, Any] | None:
    if not paths.proxy_backup.exists():
        return None
    try:
        return json.loads(paths.proxy_backup.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def is_port_free(host: str, port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind((host, port))
            return True
        except OSError:
            return False


def find_free_port(host: str, start: int, attempts: int = 20) -> int:
    for port in range(start, min(65535, start + attempts)):
        if is_port_free(host, port):
            return port
    raise SystemControlError(f"No free TCP port near {start}")


def env_snippet(port: int, cert_path: Path) -> str:
    cert = str(cert_path)
    if sys.platform != "win32":
        quoted = shlex.quote(cert)
        return f"""# EgressScope - agent environment (source this file in the current shell)
export HTTP_PROXY="http://127.0.0.1:{port}"
export HTTPS_PROXY="http://127.0.0.1:{port}"
export ALL_PROXY="http://127.0.0.1:{port}"
export NO_PROXY="localhost,127.0.0.1,::1"
export NODE_USE_ENV_PROXY=1
export NODE_EXTRA_CA_CERTS={quoted}
export REQUESTS_CA_BUNDLE={quoted}
export SSL_CERT_FILE={quoted}
export CURL_CA_BUNDLE={quoted}
echo "EgressScope proxy env applied for this shell."
"""
    return f"""@echo off
chcp 65001 >nul
REM EgressScope - agent environment (this cmd window only)
set "HTTP_PROXY=http://127.0.0.1:{port}"
set "HTTPS_PROXY=http://127.0.0.1:{port}"
set "ALL_PROXY=http://127.0.0.1:{port}"
set "NO_PROXY=localhost,127.0.0.1"
set "NODE_USE_ENV_PROXY=1"
set "NODE_EXTRA_CA_CERTS={cert}"
set "REQUESTS_CA_BUNDLE={cert}"
set "SSL_CERT_FILE={cert}"
set "CURL_CA_BUNDLE={cert}"
echo EgressScope proxy env applied for this window.
"""


def agent_env_path(paths: AppPaths) -> Path:
    name = "agent-env.cmd" if sys.platform == "win32" else "agent-env.sh"
    return paths.data / name


def write_agent_env(paths: AppPaths, port: int) -> Path:
    path = agent_env_path(paths)
    path.write_text(env_snippet(port, paths.ca_cert_pem), encoding="utf-8")
    if sys.platform != "win32":
        try:
            path.chmod(0o700)
        except OSError:
            pass
    return path
