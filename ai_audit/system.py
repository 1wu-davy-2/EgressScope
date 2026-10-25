from __future__ import annotations

import ctypes
import ipaddress
import json
import os
import shlex
import socket
import subprocess
import sys
import threading
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
RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
RUN_VALUE = "EgressScope"
CA_CN = "EgressScope Local Audit CA"
GUARD_TASK = "EgressScope Proxy Recovery"
AUDIT_TASK = "EgressScope Audit"
GUARD_SCRIPT = "proxy-guard.ps1"
GUARD_LOG = "proxy-recovery.log"
TASK_CACHE_TTL = 300.0
_task_cache: dict[str, tuple[float, bool]] = {}


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


def _proxy_endpoints(server: str) -> list[tuple[str, str, int | None]]:
    endpoints: list[tuple[str, str, int | None]] = []
    for raw in str(server or "").split(";"):
        part = raw.strip()
        if not part:
            continue
        scheme = "http"
        addr = part
        if "=" in part:
            scheme, addr = part.split("=", 1)
            scheme = scheme.strip().lower()
            addr = addr.strip()
        if not addr:
            continue
        try:
            parsed = urlsplit(addr if "://" in addr else "//" + addr)
            port = parsed.port
        except ValueError:
            continue
        endpoints.append((scheme, (parsed.hostname or "").lower(), port))
    return endpoints


def _server_has_port(server: str, port: int) -> bool:
    if not port:
        return False
    for scheme, host, candidate in _proxy_endpoints(server):
        if scheme not in ("http", "https") or candidate != port:
            continue
        if host in ("127.0.0.1", "localhost", "::1"):
            return True
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
    ours = bool(expected_port) and _server_has_port(server, int(expected_port))
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


def _save_proxy_backup(paths: AppPaths, backup: dict[str, Any]) -> None:
    tmp = paths.proxy_backup.with_suffix(".tmp")
    tmp.write_text(json.dumps(backup, indent=2, ensure_ascii=False), encoding="utf-8")
    os.replace(tmp, paths.proxy_backup)


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
    else:
        backup["managed"] = True
        backup["host"] = "127.0.0.1"
        backup["port"] = port
    _save_proxy_backup(paths, backup)
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


def restore_system_proxy(paths: AppPaths, remove_guard: bool = True) -> dict[str, Any]:
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
    guard = uninstall_proxy_guard(paths) if remove_guard else {"ok": True, "skipped": True}
    return {
        "ok": True,
        "notified": notified,
        "state": proxy_state(),
        "guard": guard,
        "restored_at": time.time(),
    }


def load_proxy_backup(paths: AppPaths) -> dict[str, Any] | None:
    if not paths.proxy_backup.exists():
        return None
    try:
        return json.loads(paths.proxy_backup.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _backup_port(backup: dict[str, Any] | None) -> int:
    if not backup:
        return 0
    try:
        return int(backup.get("port") or 0)
    except (TypeError, ValueError):
        return 0


def is_proxy_alive(port: int, timeout: float = 0.6) -> bool:
    if not port:
        return False
    try:
        with socket.create_connection(("127.0.0.1", int(port)), timeout=timeout):
            return True
    except OSError:
        return False


def _write_proxy_server(port: int) -> None:
    import winreg

    with _open_internet_settings() as key:
        winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, f"127.0.0.1:{port}")


def reconcile_system_proxy(paths: AppPaths, port: int) -> dict[str, Any]:
    """Point a previously managed system proxy at the current live port.

    Windows persists the per-user system proxy across reboots. If EgressScope
    starts on a different port after an unclean exit, the stale registry value
    would send traffic to a dead port.
    """
    supported = sys.platform == "win32"
    backup = load_proxy_backup(paths)
    if not backup:
        return {"supported": supported, "action": "noop", "reason": "no-backup"}
    previous = _backup_port(backup)
    if not previous:
        return {"supported": supported, "action": "noop", "reason": "invalid-backup"}
    state = proxy_state(previous)
    if not state.get("ours"):
        return {"supported": supported, "action": "noop", "reason": "not-managed", "previous_port": previous}
    if previous == port:
        return {"supported": supported, "action": "healthy", "port": port}
    _write_proxy_server(port)
    _notify_settings_changed()
    backup["port"] = port
    backup["reconciled_at"] = time.time()
    _save_proxy_backup(paths, backup)
    return {"supported": supported, "action": "repointed", "previous_port": previous, "port": port}


def recover_stale_proxy(paths: AppPaths, grace_seconds: float = 0.0) -> dict[str, Any]:
    """Restore the original proxy if our managed proxy is no longer listening."""
    supported = sys.platform == "win32"
    backup = load_proxy_backup(paths)
    if not backup:
        return {"supported": supported, "action": "noop", "reason": "no-backup"}
    port = _backup_port(backup)
    if not port:
        return {"supported": supported, "action": "noop", "reason": "invalid-backup"}
    if not proxy_state(port).get("ours"):
        return {"supported": supported, "action": "noop", "reason": "not-managed", "port": port}
    deadline = time.time() + max(0.0, float(grace_seconds or 0))
    while True:
        if is_proxy_alive(port):
            return {"supported": supported, "action": "noop", "reason": "healthy", "port": port}
        remaining = deadline - time.time()
        if remaining <= 0:
            break
        time.sleep(min(2.0, remaining))
    result = restore_system_proxy(paths)
    return {"supported": supported, "action": "restored", "port": port, "restore": result}


# ---------- independent proxy guard ----------
GUARD_SCRIPT_TEMPLATE = r'''param(
    [Parameter(Mandatory=$true)][string]$Backup,
    [Parameter(Mandatory=$true)][string]$Log,
    [int]$GraceSeconds = 20
)

$ErrorActionPreference = "SilentlyContinue"

function Write-GuardLog([string]$Message) {
    try {
        $dir = Split-Path -Parent $Log
        if ($dir -and -not (Test-Path -LiteralPath $dir)) {
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
        }
        Add-Content -LiteralPath $Log -Value ("{0} {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Message) -Encoding UTF8
    } catch { }
}

function Test-EgressScopeListener([int]$Port) {
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $async = $client.BeginConnect("127.0.0.1", $Port, $null, $null)
        if (-not $async.AsyncWaitHandle.WaitOne(800)) { return $false }
        $client.EndConnect($async)
        return $true
    } catch {
        return $false
    } finally {
        $client.Close()
    }
}

$regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"

function Get-EgressScopeLoopbackPort {
    $current = Get-ItemProperty -Path $regPath
    if ($null -eq $current -or [int]$current.ProxyEnable -ne 1) { return 0 }
    foreach ($part in ([string]$current.ProxyServer).Split(";")) {
        $piece = $part.Trim()
        if (-not $piece) { continue }
        $scheme = "http"
        $addr = $piece
        if ($piece.Contains("=")) {
            $scheme = $piece.Split("=", 2)[0].Trim().ToLower()
            $addr = $piece.Split("=", 2)[1].Trim()
        }
        if ($scheme -ne "http" -and $scheme -ne "https") { continue }
        if ($addr -match '^(127\.0\.0\.1|localhost):(\d+)$') { return [int]$Matches[2] }
    }
    return 0
}

$deadline = (Get-Date).AddSeconds($GraceSeconds)
while ($true) {
    if (-not (Test-Path -LiteralPath $Backup)) { exit 0 }
    $port = Get-EgressScopeLoopbackPort
    if ($port -lt 1) { exit 0 }
    if (Test-EgressScopeListener $port) { exit 0 }
    if ((Get-Date) -ge $deadline) { break }
    Start-Sleep -Seconds 2
}
$port = Get-EgressScopeLoopbackPort
if ($port -lt 1 -or (Test-EgressScopeListener $port)) { exit 0 }

try {
    $backup = Get-Content -LiteralPath $Backup -Raw -Encoding UTF8 | ConvertFrom-Json
    if ($null -eq $backup.values) { throw "backup has no values" }
} catch {
    Write-GuardLog "backup file became unreadable; leaving the system proxy untouched"
    exit 0
}

$failed = $false
foreach ($name in @("ProxyEnable", "ProxyServer", "ProxyOverride", "AutoConfigURL")) {
    $value = $backup.values.$name
    try {
        if ($null -eq $value) {
            if (Get-ItemProperty -Path $regPath -Name $name -ErrorAction SilentlyContinue) {
                Remove-ItemProperty -Path $regPath -Name $name -ErrorAction Stop
            }
        } elseif ($name -eq "ProxyEnable") {
            Set-ItemProperty -Path $regPath -Name $name -Value ([int]$value) -Type DWord -ErrorAction Stop
        } else {
            Set-ItemProperty -Path $regPath -Name $name -Value ([string]$value) -Type String -ErrorAction Stop
        }
    } catch {
        $failed = $true
        Write-GuardLog ("failed to restore {0}: {1}" -f $name, $_.Exception.Message)
    }
}

$signature = @"
using System;
using System.Runtime.InteropServices;
public static class EgressScopeWinInet {
    [DllImport("wininet.dll", SetLastError = true)]
    public static extern bool InternetSetOption(IntPtr hInternet, int option, IntPtr buffer, int length);
}
"@
try {
    Add-Type -TypeDefinition $signature
    [EgressScopeWinInet]::InternetSetOption([IntPtr]::Zero, 39, [IntPtr]::Zero, 0) | Out-Null
    [EgressScopeWinInet]::InternetSetOption([IntPtr]::Zero, 37, [IntPtr]::Zero, 0) | Out-Null
} catch {
    Write-GuardLog "WinINet refresh failed; sign out and back in if a browser still shows no network"
}

if ($failed) {
    Write-GuardLog "restore incomplete; backup kept for the next guard run"
    exit 1
}

Remove-Item -LiteralPath $Backup -Force
Write-GuardLog "restored the original system proxy because 127.0.0.1:$port was not listening"
schtasks.exe /Change /TN "__GUARD_TASK__" /DISABLE | Out-Null
schtasks.exe /Change /TN "__AUDIT_TASK__" /DISABLE | Out-Null
exit 0
'''


def _guard_script_text() -> str:
    return GUARD_SCRIPT_TEMPLATE.replace("__GUARD_TASK__", GUARD_TASK).replace("__AUDIT_TASK__", AUDIT_TASK)


def guard_script_path(paths: AppPaths) -> Path:
    return paths.data / GUARD_SCRIPT


def guard_log_path(paths: AppPaths) -> Path:
    return paths.logs / GUARD_LOG


def _task_exists(name: str) -> bool:
    if sys.platform != "win32":
        return False
    now = time.time()
    cached = _task_cache.get(name)
    if cached and now - cached[0] < TASK_CACHE_TTL:
        return cached[1]
    try:
        result = subprocess.run(
            ["schtasks", "/Query", "/TN", name],
            capture_output=True,
            text=True,
            errors="replace",
            timeout=20,
            creationflags=CREATE_NO_WINDOW,
        )
        exists = result.returncode == 0
    except (OSError, subprocess.SubprocessError):
        exists = False
    _task_cache[name] = (now, exists)
    return exists


def _guard_task_cached() -> bool | None:
    """Return the cached guard task state without spawning schtasks."""
    if sys.platform != "win32":
        return None
    cached = _task_cache.get(GUARD_TASK)
    if not cached or time.time() - cached[0] >= TASK_CACHE_TTL:
        return None
    return cached[1]


def proxy_guard_status(paths: AppPaths) -> dict[str, Any]:
    backup = load_proxy_backup(paths)
    guard = (backup or {}).get("guard") or {}
    script_exists = guard_script_path(paths).exists()
    enabled = bool(guard.get("enabled"))
    task_present = _guard_task_cached()
    return {
        "supported": sys.platform == "win32",
        "enabled": enabled,
        "installed": enabled and script_exists,
        "degraded": enabled and (not script_exists or task_present is False),
        "task_present": task_present,
        "script": str(guard_script_path(paths)),
        "log": str(guard_log_path(paths)),
        "recovery_task": GUARD_TASK,
        "audit_task": AUDIT_TASK,
        "interval_minutes": 2,
        "autostart": autostart_status(paths),
    }


def _register_scheduled_task(
    name: str,
    command: str,
    arguments: str,
    repeat_minutes: int = 0,
    limit_minutes: int = 0,
) -> dict[str, Any]:
    """Register a per-user interactive task without elevation.

    schtasks /SC ONLOGON and raw task XML are rejected for standard users on
    some Windows configurations; the ScheduledTasks object model is not.
    """
    env = os.environ.copy()
    env.update({
        "EGRESS_TASK_NAME": name,
        "EGRESS_TASK_EXE": command,
        "EGRESS_TASK_ARGS": arguments,
        "EGRESS_TASK_REPEAT": str(max(0, int(repeat_minutes))),
        "EGRESS_TASK_LIMIT": str(max(0, int(limit_minutes))),
    })
    script = r'''
$ErrorActionPreference = "Stop"
$me = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
$action = New-ScheduledTaskAction -Execute $env:EGRESS_TASK_EXE -Argument $env:EGRESS_TASK_ARGS
$limit = [TimeSpan]::Zero
if ([int]$env:EGRESS_TASK_LIMIT -gt 0) { $limit = New-TimeSpan -Minutes ([int]$env:EGRESS_TASK_LIMIT) }
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -MultipleInstances IgnoreNew -ExecutionTimeLimit $limit
$triggers = @(New-ScheduledTaskTrigger -AtLogOn -User $me)
if ([int]$env:EGRESS_TASK_REPEAT -gt 0) {
    $triggers += New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes ([int]$env:EGRESS_TASK_REPEAT))
}
$principal = New-ScheduledTaskPrincipal -UserId $me -LogonType Interactive -RunLevel Limited
Register-ScheduledTask -TaskName $env:EGRESS_TASK_NAME -Action $action -Trigger $triggers -Settings $settings -Principal $principal -Force | Out-Null
'''
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True,
            text=True,
            errors="replace",
            timeout=90,
            creationflags=CREATE_NO_WINDOW,
            env=env,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return {"ok": False, "returncode": -1, "message": str(exc)}
    message = (result.stdout or result.stderr or "").strip()[-1200:]
    return {"ok": result.returncode == 0, "returncode": result.returncode, "message": message}


def _remove_task(name: str, disable_only: bool = False) -> dict[str, Any]:
    query = subprocess.run(
        ["schtasks", "/Query", "/TN", name],
        capture_output=True,
        text=True,
        errors="replace",
        timeout=60,
        creationflags=CREATE_NO_WINDOW,
    )
    if query.returncode != 0:
        return {"ok": True, "disabled": disable_only, "message": "task not present"}
    command = ["schtasks", "/Change", "/TN", name, "/DISABLE"] if disable_only else ["schtasks", "/Delete", "/TN", name, "/F"]
    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        errors="replace",
        timeout=60,
        creationflags=CREATE_NO_WINDOW,
    )
    output = (result.stdout or result.stderr or "").strip()
    return {"ok": result.returncode == 0, "disabled": disable_only, "message": output[-800:]}


def _launch_command(paths: AppPaths) -> tuple[str, str]:
    exe = sys.executable
    prefix: list[str] = []
    if not getattr(sys, "frozen", False):
        pythonw = Path(exe).with_name("pythonw.exe")
        if pythonw.exists():
            exe = str(pythonw)
        prefix = [str(Path(__file__).resolve().parent.parent / "app.py")]
    arguments = prefix + ["--autostart", "--home", str(paths.home)]
    return exe, subprocess.list2cmdline(arguments)


def autostart_command(paths: AppPaths) -> str:
    exe, arguments = _launch_command(paths)
    return subprocess.list2cmdline([exe]) + " " + arguments


def _run_key_read() -> str:
    import winreg

    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY, 0, winreg.KEY_READ) as key:
            return str(winreg.QueryValueEx(key, RUN_VALUE)[0])
    except FileNotFoundError:
        return ""
    except OSError:
        return ""


def autostart_status(paths: AppPaths) -> dict[str, Any]:
    if sys.platform != "win32":
        return {"supported": False, "enabled": False, "ours": False, "stale": False, "command": "", "value": ""}
    value = _run_key_read()
    expected = autostart_command(paths)
    ours = bool(value) and value == expected
    return {
        "supported": True,
        "enabled": bool(value),
        "ours": ours,
        "stale": bool(value) and not ours,
        "command": expected,
        "value": value,
    }


def enable_autostart(paths: AppPaths) -> dict[str, Any]:
    if sys.platform != "win32":
        raise SystemControlError("开机自启只支持 Windows")
    import winreg

    command = autostart_command(paths)
    with winreg.CreateKey(winreg.HKEY_CURRENT_USER, RUN_KEY) as key:
        winreg.SetValueEx(key, RUN_VALUE, 0, winreg.REG_SZ, command)
    return {"ok": True, "enabled": True, "command": command}


def disable_autostart(paths: AppPaths) -> dict[str, Any]:
    if sys.platform != "win32":
        return {"ok": True, "supported": False, "enabled": False}
    import winreg

    value = _run_key_read()
    if not value:
        return {"ok": True, "enabled": False, "removed": False}
    if value != autostart_command(paths):
        return {"ok": True, "enabled": True, "removed": False, "reason": "not-ours"}
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY, 0, winreg.KEY_SET_VALUE) as key:
            winreg.DeleteValue(key, RUN_VALUE)
    except FileNotFoundError:
        pass
    return {"ok": True, "enabled": False, "removed": True}


def repair_integrations(paths: AppPaths, want_autostart: bool, want_guard: bool) -> dict[str, Any]:
    """Rewrite per-user autostart and watchdog integrations for this executable."""
    at = time.time()
    if sys.platform != "win32":
        return {
            "supported": False,
            "ok": True,
            "autostart": {"action": "noop", "reason": "unsupported-platform", "ok": True},
            "guard": {"action": "noop", "reason": "unsupported-platform", "ok": True},
            "at": at,
        }

    autostart: dict[str, Any] = {"action": "none", "ok": True}
    try:
        value = _run_key_read()
        expected = autostart_command(paths)
        autostart.update(command=expected, value=value, stale=bool(value) and value != expected)
        if want_autostart:
            if value == expected:
                autostart.update(action="healthy", ok=True)
            else:
                enable_autostart(paths)
                autostart.update(action="repointed" if value else "registered", ok=True)
        elif not value:
            autostart.update(action="healthy", ok=True)
        elif value == expected:
            result = disable_autostart(paths)
            autostart.update(action="removed", ok=bool(result.get("ok", True)))
        else:
            autostart.update(action="skipped", reason="not-ours", ok=True)
    except Exception as exc:
        autostart.update(action="error" if autostart.get("action") == "none" else autostart["action"], ok=False)
        autostart["error"] = f"{type(exc).__name__}: {exc}"

    guard: dict[str, Any] = {"action": "none", "ok": True}
    try:
        backup = load_proxy_backup(paths) or {}
        guard_enabled = bool((backup.get("guard") or {}).get("enabled"))
        guard["enabled"] = guard_enabled
        if not want_guard:
            guard.update(action="skipped", reason="disabled", ok=True)
        elif not guard_enabled:
            guard.update(action="skipped", reason="not-enabled", ok=True)
        else:
            script = guard_script_path(paths)
            script_exists = script.exists()
            task_present = _task_exists(GUARD_TASK)
            guard.update(script=str(script), script_present=script_exists, task_present=task_present)
            if script_exists and task_present:
                guard.update(action="healthy", ok=True)
            else:
                guard.update(action="reinstalled")
                result = install_proxy_guard(paths)
                guard.update(ok=bool(result.get("ok")), install=result, action="reinstalled")
                if result.get("ok"):
                    _task_cache[GUARD_TASK] = (time.time(), True)
    except Exception as exc:
        guard.update(action="error" if guard.get("action") == "none" else guard["action"], ok=False)
        guard["error"] = f"{type(exc).__name__}: {exc}"

    return {
        "supported": True,
        "ok": bool(autostart.get("ok") and guard.get("ok")),
        "autostart": autostart,
        "guard": guard,
        "at": at,
    }


def install_proxy_guard(paths: AppPaths) -> dict[str, Any]:
    if sys.platform != "win32":
        raise SystemControlError("断网保护只支持 Windows")
    backup = load_proxy_backup(paths)
    if not backup:
        raise SystemControlError("请先启用系统代理，再启用断网保护")
    script = guard_script_path(paths)
    script.parent.mkdir(parents=True, exist_ok=True)
    script.write_text(_guard_script_text(), encoding="utf-8-sig")

    system_root = Path(os.environ.get("SystemRoot") or r"C:\Windows")
    powershell = system_root / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
    powershell_cmd = str(powershell) if powershell.exists() else "powershell.exe"
    guard_args = subprocess.list2cmdline([
        "-NoProfile",
        "-NonInteractive",
        "-WindowStyle",
        "Hidden",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        str(script),
        "-Backup",
        str(paths.proxy_backup),
        "-Log",
        str(guard_log_path(paths)),
        "-GraceSeconds",
        "30",
    ])
    recovery_result = _register_scheduled_task(GUARD_TASK, powershell_cmd, guard_args, repeat_minutes=2, limit_minutes=5)

    # Logon start is handled by the per-user Run key (autostart), not by a task.
    audit_result = {"ok": True, "skipped": True, "reason": "logon start uses the Run key autostart"}

    if recovery_result.get("ok"):
        guard = {
            "enabled": True,
            "installed_at": time.time(),
            "script": str(script),
            "recovery_task": GUARD_TASK,
            "audit_task": AUDIT_TASK,
        }
        backup["guard"] = guard
        _save_proxy_backup(paths, backup)
        _task_cache[GUARD_TASK] = (time.time(), True)
    return {
        "ok": bool(recovery_result.get("ok")),
        "recovery_task": recovery_result,
        "audit_task": audit_result,
        "script": str(script),
        "log": str(guard_log_path(paths)),
        "recovery_task_name": GUARD_TASK,
        "audit_task_name": AUDIT_TASK,
    }


def uninstall_proxy_guard(paths: AppPaths, disable_only: bool = False) -> dict[str, Any]:
    if sys.platform != "win32":
        return {"ok": True, "supported": False}
    results = {
        "recovery": _remove_task(GUARD_TASK, disable_only=disable_only),
        "audit": _remove_task(AUDIT_TASK, disable_only=disable_only),
    }
    if not disable_only:
        _task_cache.pop(GUARD_TASK, None)
        _task_cache.pop(AUDIT_TASK, None)
        try:
            (paths.data / GUARD_SCRIPT).unlink(missing_ok=True)
        except OSError:
            pass
        backup = load_proxy_backup(paths)
        if backup and backup.get("guard"):
            backup.pop("guard", None)
            _save_proxy_backup(paths, backup)
    return {
        "ok": all(item.get("ok") for item in results.values()),
        "disabled": disable_only,
        "tasks": results,
    }


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


# ---------- graceful shutdown / logoff hook ----------
WM_QUERYENDSESSION = 0x0018
WM_ENDSESSION = 0x0016
CTRL_LOGOFF_EVENT = 5
CTRL_SHUTDOWN_EVENT = 6
WS_POPUP = 0x80000000
WS_EX_TOOLWINDOW = 0x00000080
WS_EX_NOACTIVATE = 0x08000000
GA_ROOT = 2

_shutdown_hook_installed = False
_shutdown_hook_state: dict[str, Any] = {}
_shutdown_window_refs: list[Any] = []


def install_shutdown_hook(on_shutdown) -> dict[str, Any]:
    """Run ``on_shutdown`` when Windows shuts down or the user logs off.

    The GUI channel uses a hidden top-level window created on its own message
    thread. Message-only windows are not top-level and do not receive session
    end notifications, so they cannot observe shutdown or logoff. A console
    control handler covers console builds. Both channels must return quickly;
    the callback only touches the registry and WinINET.
    """
    global _shutdown_hook_installed
    if sys.platform != "win32":
        return {"supported": False, "window": False, "top_level": False, "hwnd": 0, "console": False}
    if _shutdown_hook_installed:
        return dict(_shutdown_hook_state)
    _shutdown_hook_installed = True
    window = _install_window_hook(on_shutdown)
    console_ok = _install_console_hook(on_shutdown)
    _shutdown_hook_state.update(
        supported=True,
        window=bool(window.get("ok")),
        top_level=bool(window.get("top_level")),
        hwnd=int(window.get("hwnd") or 0),
        console=console_ok,
        error=str(window.get("error") or ""),
    )
    return dict(_shutdown_hook_state)


def _install_window_hook(on_shutdown) -> dict[str, Any]:
    try:
        import ctypes
        from ctypes import wintypes
    except Exception:
        return {"ok": False, "hwnd": 0, "top_level": False}

    user32 = ctypes.windll.user32
    kernel32 = ctypes.windll.kernel32
    WNDPROC = ctypes.WINFUNCTYPE(ctypes.c_ssize_t, wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM)

    kernel32.GetModuleHandleW.restype = wintypes.HMODULE
    kernel32.GetModuleHandleW.argtypes = [wintypes.LPCWSTR]
    user32.CreateWindowExW.restype = wintypes.HWND
    user32.CreateWindowExW.argtypes = [
        wintypes.DWORD,
        wintypes.LPCWSTR,
        wintypes.LPCWSTR,
        wintypes.DWORD,
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_int,
        wintypes.HWND,
        wintypes.HMENU,
        wintypes.HINSTANCE,
        wintypes.LPVOID,
    ]
    user32.DefWindowProcW.restype = ctypes.c_ssize_t
    user32.DefWindowProcW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
    user32.GetAncestor.restype = wintypes.HWND
    user32.GetAncestor.argtypes = [wintypes.HWND, wintypes.UINT]
    user32.ShutdownBlockReasonCreate.restype = wintypes.BOOL
    user32.ShutdownBlockReasonCreate.argtypes = [wintypes.HWND, wintypes.LPCWSTR]
    user32.ShutdownBlockReasonDestroy.restype = wintypes.BOOL
    user32.ShutdownBlockReasonDestroy.argtypes = [wintypes.HWND]

    def wndproc(hwnd, msg, wparam, lparam):
        if msg == WM_QUERYENDSESSION:
            try:
                user32.ShutdownBlockReasonCreate(hwnd, "EgressScope is restoring the system proxy")
            except Exception:
                pass
            _run_shutdown_callback(on_shutdown, "queryendsession")
            try:
                user32.ShutdownBlockReasonDestroy(hwnd)
            except Exception:
                pass
            return 1
        if msg == WM_ENDSESSION:
            if wparam:
                _run_shutdown_callback(on_shutdown, "endsession")
            return 0
        return user32.DefWindowProcW(hwnd, msg, wparam, lparam)

    callback = WNDPROC(wndproc)
    ready = threading.Event()
    result: dict[str, Any] = {"ok": False, "hwnd": 0, "top_level": False}

    def pump() -> None:
        global _shutdown_window_refs
        try:
            class WNDCLASSW(ctypes.Structure):
                _fields_ = [
                    ("style", wintypes.UINT),
                    ("lpfnWndProc", WNDPROC),
                    ("cbClsExtra", ctypes.c_int),
                    ("cbWndExtra", ctypes.c_int),
                    ("hInstance", wintypes.HINSTANCE),
                    ("hIcon", wintypes.HICON),
                    ("hCursor", ctypes.c_void_p),
                    ("hbrBackground", wintypes.HBRUSH),
                    ("lpszMenuName", wintypes.LPCWSTR),
                    ("lpszClassName", wintypes.LPCWSTR),
                ]

            wc = WNDCLASSW()
            wc.lpfnWndProc = callback
            wc.hInstance = kernel32.GetModuleHandleW(None)
            wc.lpszClassName = "EgressScopeShutdownGuard"
            if not user32.RegisterClassW(ctypes.byref(wc)):
                error = kernel32.GetLastError()
                if error != 1410:
                    result["error"] = f"RegisterClassW failed: {error}"
                    ready.set()
                    return
            hwnd = user32.CreateWindowExW(
                WS_EX_TOOLWINDOW | WS_EX_NOACTIVATE,
                wc.lpszClassName,
                "EgressScope Shutdown Guard",
                WS_POPUP,
                0,
                0,
                0,
                0,
                None,
                None,
                wc.hInstance,
                None,
            )
            if not hwnd:
                result["error"] = f"CreateWindowExW failed: {kernel32.GetLastError()}"
                ready.set()
                return
            root = user32.GetAncestor(hwnd, GA_ROOT)
            result.update(ok=True, hwnd=int(hwnd), top_level=root is not None and int(root) == int(hwnd))
            _shutdown_window_refs = [callback, wc, hwnd]
            ready.set()
            msg = wintypes.MSG()
            while user32.GetMessageW(ctypes.byref(msg), None, 0, 0) > 0:
                user32.TranslateMessage(ctypes.byref(msg))
                user32.DispatchMessageW(ctypes.byref(msg))
        except Exception as exc:
            result["error"] = f"{type(exc).__name__}: {exc}"
            ready.set()

    threading.Thread(target=pump, name="egressscope-shutdown", daemon=True).start()
    ready.wait(5)
    return result


def _install_console_hook(on_shutdown) -> bool:
    try:
        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.windll.kernel32
        if not kernel32.GetConsoleWindow():
            return False
        HANDLER = ctypes.WINFUNCTYPE(ctypes.c_int, wintypes.DWORD)

        def handler(event):
            if event in (CTRL_LOGOFF_EVENT, CTRL_SHUTDOWN_EVENT):
                _run_shutdown_callback(on_shutdown, "console")
                return 1
            return 0

        callback = HANDLER(handler)
        kernel32._egress_ctrl_handler = callback
        return bool(kernel32.SetConsoleCtrlHandler(callback, True))
    except Exception:
        return False


def _run_shutdown_callback(on_shutdown, source: str) -> None:
    try:
        on_shutdown(source)
    except Exception:
        pass
