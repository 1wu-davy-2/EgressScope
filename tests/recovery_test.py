"""Focused tests for fail-open system proxy recovery.

These tests never read or write the real Windows proxy registry. Run from the
project root:

    .venv/Scripts/python.exe tests/recovery_test.py
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ai_audit import system
from ai_audit.paths import AppPaths

PASSED: list[str] = []
FAILED: list[str] = []


def check(name: str, condition: bool, detail: str = "") -> None:
    if condition:
        PASSED.append(name)
        print(f"  PASS  {name}")
    else:
        FAILED.append(name)
        print(f"  FAIL  {name}{(' — ' + detail) if detail else ''}")
        if os.environ.get("GITHUB_ACTIONS"):
            print(f"::error title=EgressScope test::{name} {detail}".rstrip())


def proxy_backup(port: int = 8899) -> dict:
    return {
        "created_at": 1.0,
        "managed": True,
        "host": "127.0.0.1",
        "port": port,
        "values": {
            "ProxyEnable": 1,
            "ProxyServer": "10.10.10.10:3128",
            "ProxyOverride": "*.internal;<local>",
            "AutoConfigURL": None,
        },
    }


def write_backup(paths: AppPaths, payload: dict) -> None:
    paths.proxy_backup.write_text(json.dumps(payload), encoding="utf-8")


def test_endpoint_matching() -> None:
    check("plain loopback proxy matches its exact port", system._server_has_port("127.0.0.1:8899", 8899))
    check("localhost proxy matches", system._server_has_port("localhost:8899", 8899))
    check("scheme list matches", system._server_has_port("http=127.0.0.1:8899;https=127.0.0.1:8899", 8899))
    check("longer port does not prefix-match", not system._server_has_port("127.0.0.1:88990", 8899))
    check("remote proxy is not treated as ours", not system._server_has_port("10.0.0.1:8899", 8899))
    check("SOCKS loopback is not treated as ours", not system._server_has_port("socks=127.0.0.1:8899", 8899))
    check("empty proxy is not treated as ours", not system._server_has_port("", 8899))


def test_recover_stale() -> None:
    with tempfile.TemporaryDirectory(prefix="egressscope-recovery-") as temp:
        paths = AppPaths(Path(temp) / "home")
        paths.ensure()

        result = system.recover_stale_proxy(paths)
        check("recovery without backup is a no-op", result.get("action") == "noop" and result.get("reason") == "no-backup")

        write_backup(paths, proxy_backup())
        restored: list[bool] = []

        def fake_restore(_paths):
            restored.append(True)
            return {"ok": True, "state": {}}

        with mock.patch.object(system, "proxy_state", return_value={"ours": True}), \
             mock.patch.object(system, "is_proxy_alive", return_value=False), \
             mock.patch.object(system, "restore_system_proxy", side_effect=fake_restore):
            result = system.recover_stale_proxy(paths)
        check("dead managed proxy is restored", result.get("action") == "restored", str(result))
        check("restore is called exactly once", len(restored) == 1)

        with mock.patch.object(system, "proxy_state", return_value={"ours": True}), \
             mock.patch.object(system, "is_proxy_alive", return_value=True), \
             mock.patch.object(system, "restore_system_proxy", side_effect=AssertionError("must not restore")):
            result = system.recover_stale_proxy(paths)
        check("live proxy is left alone", result.get("reason") == "healthy", str(result))

        with mock.patch.object(system, "proxy_state", return_value={"ours": False}), \
             mock.patch.object(system, "restore_system_proxy", side_effect=AssertionError("must not restore")):
            result = system.recover_stale_proxy(paths)
        check("externally changed proxy is left alone", result.get("reason") == "not-managed", str(result))


def test_reconcile() -> None:
    with tempfile.TemporaryDirectory(prefix="egressscope-reconcile-") as temp:
        paths = AppPaths(Path(temp) / "home")
        paths.ensure()
        write_backup(paths, proxy_backup(8899))
        written: list[int] = []
        with mock.patch.object(system, "proxy_state", return_value={"ours": True}), \
             mock.patch.object(system, "_write_proxy_server", side_effect=lambda port: written.append(port)), \
             mock.patch.object(system, "_notify_settings_changed", return_value=True):
            result = system.reconcile_system_proxy(paths, 8907)
        updated = json.loads(paths.proxy_backup.read_text(encoding="utf-8"))
        check("stale proxy is repointed to the live port", result.get("action") == "repointed" and written == [8907], str(result))
        check("backup records the new port", updated.get("port") == 8907, str(updated.get("port")))

        with mock.patch.object(system, "proxy_state", return_value={"ours": True}), \
             mock.patch.object(system, "_write_proxy_server", side_effect=AssertionError("must not rewrite")):
            result = system.reconcile_system_proxy(paths, 8907)
        check("same port is a no-op", result.get("action") == "healthy", str(result))

        with mock.patch.object(system, "proxy_state", return_value={"ours": False}), \
             mock.patch.object(system, "_write_proxy_server", side_effect=AssertionError("must not rewrite")):
            result = system.reconcile_system_proxy(paths, 8910)
        check("external proxy is never overwritten", result.get("reason") == "not-managed", str(result))


def test_guard_script() -> None:
    text = system._guard_script_text()
    check("guard script has no placeholders", "__GUARD_TASK__" not in text and "__AUDIT_TASK__" not in text)
    check("guard script checks the managed port", "Test-EgressScopeListener" in text and "ProxyEnable" in text)
    check("guard script restores the backup", "ConvertFrom-Json" in text and "Remove-Item -LiteralPath $Backup" in text)
    check("guard disables itself after recovery", system.GUARD_TASK in text and "/DISABLE" in text)

    if sys.platform == "win32":
        with tempfile.TemporaryDirectory(prefix="egressscope-ps-") as temp:
            script = Path(temp) / "guard.ps1"
            script.write_text(text, encoding="utf-8-sig")
            env = {**os.environ, "EGRESS_GUARD_TEST": str(script)}
            command = (
                "$errors = $null; "
                "[void][System.Management.Automation.Language.Parser]::ParseFile("
                "$env:EGRESS_GUARD_TEST, [ref]$null, [ref]$errors); "
                "if ($errors.Count -gt 0) { $errors | ForEach-Object { Write-Output $_.Message }; exit 1 }"
            )
            result = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", command],
                capture_output=True,
                text=True,
                errors="replace",
                timeout=60,
                env=env,
            )
            check("guard PowerShell parses on Windows", result.returncode == 0, (result.stdout or result.stderr)[-500:])


def test_windows_task_registration() -> None:
    if sys.platform != "win32":
        return
    name = f"EgressScope CI Validation {os.getpid()}"
    try:
        result = system._register_scheduled_task(name, "cmd.exe", "/c exit 0", repeat_minutes=2, limit_minutes=1)
        check("Windows accepts a per-user guard task", bool(result.get("ok")), str(result.get("message")))
        query = subprocess.run(
            ["schtasks", "/Query", "/TN", name],
            capture_output=True,
            text=True,
            errors="replace",
            timeout=60,
        )
        check("registered validation task is queryable", query.returncode == 0)
    finally:
        system._remove_task(name)
        query = subprocess.run(
            ["schtasks", "/Query", "/TN", name],
            capture_output=True,
            text=True,
            errors="replace",
            timeout=60,
        )
        check("validation task is removed", query.returncode != 0)


def test_guard_status() -> None:
    with tempfile.TemporaryDirectory(prefix="egressscope-guard-") as temp:
        paths = AppPaths(Path(temp) / "home")
        paths.ensure()
        payload = proxy_backup()
        payload["guard"] = {"enabled": True, "script": str(system.guard_script_path(paths))}
        write_backup(paths, payload)
        status = system.proxy_guard_status(paths)
        check("guard reports degraded when its script is missing", status.get("degraded") is True and status.get("installed") is False)
        system.guard_script_path(paths).write_text(system._guard_script_text(), encoding="utf-8-sig")
        status = system.proxy_guard_status(paths)
        check("guard reports installed when backup and script exist", status.get("installed") is True)


class _KeyContext:
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def fake_winreg_module(store: dict) -> mock.MagicMock:
    mod = mock.MagicMock()
    mod.HKEY_CURRENT_USER = "HKCU"
    mod.KEY_READ = 1
    mod.KEY_SET_VALUE = 2
    mod.REG_SZ = 3
    mod.OpenKey = mock.MagicMock(side_effect=lambda *a, **k: _KeyContext())
    mod.CreateKey = mock.MagicMock(side_effect=lambda *a, **k: _KeyContext())

    def query(_key, name):
        if name not in store:
            raise FileNotFoundError(name)
        return (store[name], mod.REG_SZ)

    mod.QueryValueEx = mock.MagicMock(side_effect=query)
    mod.SetValueEx = mock.MagicMock(side_effect=lambda key, name, _reserved, _type, value: store.__setitem__(name, value))
    mod.DeleteValue = mock.MagicMock(side_effect=lambda key, name: store.pop(name, None))
    return mod


def test_autostart() -> None:
    with tempfile.TemporaryDirectory(prefix="egressscope-autostart-") as temp:
        paths = AppPaths(Path(temp) / "home")
        paths.ensure()
        command = system.autostart_command(paths)
        check("autostart command starts the app minimized", "--autostart" in command and str(paths.home) in command, command)

        store: dict[str, str] = {}
        with mock.patch.object(sys, "platform", "win32", create=True), mock.patch.dict(sys.modules, {"winreg": fake_winreg_module(store)}):
            status = system.autostart_status(paths)
            check("autostart starts unregistered", status.get("enabled") is False, str(status))
            result = system.enable_autostart(paths)
            check("enable_autostart writes the run key", result.get("ok") is True and store.get(system.RUN_VALUE) == command, str(store))
            status = system.autostart_status(paths)
            check("autostart reports enabled and ours", status.get("enabled") is True and status.get("ours") is True, str(status))
            result = system.disable_autostart(paths)
            check("disable_autostart removes our value", result.get("removed") is True and not store, str(store))

            store[system.RUN_VALUE] = "C:\\other\\app.exe"
            result = system.disable_autostart(paths)
            check("foreign run key value is preserved", result.get("removed") is False and store.get(system.RUN_VALUE) == "C:\\other\\app.exe", str(result))


def test_config_hot_reload() -> None:
    from ai_audit.config import ConfigStore

    with tempfile.TemporaryDirectory(prefix="egressscope-config-") as temp:
        path = Path(temp) / "config.json"
        store = ConfigStore(path)
        store.update({"blocking_enabled": True})
        check("update persists editable keys", json.loads(path.read_text(encoding="utf-8")).get("blocking_enabled") is True)
        check("unchanged file reports no reload", store.reload_if_changed() == [])

        raw = json.loads(path.read_text(encoding="utf-8"))
        raw["retention_days"] = 30
        raw["listen_port"] = 1234
        path.write_text(json.dumps(raw), encoding="utf-8")
        os.utime(path, (0, 0))
        changed = store.reload_if_changed()
        check("external edit is adopted without restart", "retention_days" in changed and store.settings.retention_days == 30, str(changed))
        check("non-editable keys are ignored on reload", "listen_port" not in changed and store.settings.listen_port == 8899, str(changed))
        check("second poll reports no further change", store.reload_if_changed() == [])

        path.write_text("{ not json", encoding="utf-8")
        changed = store.reload_if_changed()
        check(
            "malformed external edit keeps current settings",
            changed == [] and store.settings.retention_days == 30 and "rejected" in store.reload_error,
            store.reload_error,
        )
        raw["retention_days"] = 45
        path.write_text(json.dumps(raw), encoding="utf-8")
        changed = store.reload_if_changed()
        check(
            "applying a valid edit clears the reload error",
            "retention_days" in changed and store.settings.retention_days == 45 and store.reload_error == "",
            str(changed),
        )
        path.unlink()
        changed = store.reload_if_changed()
        check(
            "deleting the config keeps current settings",
            changed == [] and store.settings.retention_days == 45 and "missing" in store.reload_error,
            store.reload_error,
        )


def test_shutdown_hook() -> None:
    if sys.platform != "win32":
        return
    import ctypes
    from ctypes import wintypes

    seen: list[str] = []
    hook = system.install_shutdown_hook(lambda source: seen.append(source))
    check(
        "shutdown hook creates a hidden top-level window",
        hook.get("window") is True and hook.get("top_level") is True and not hook.get("error"),
        str(hook),
    )
    hwnd = hook.get("hwnd") or 0
    if not hwnd:
        return
    user32 = ctypes.windll.user32
    user32.IsWindowVisible.argtypes = [wintypes.HWND]
    user32.IsWindowVisible.restype = wintypes.BOOL
    user32.SendMessageW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
    user32.SendMessageW.restype = ctypes.c_ssize_t
    check("shutdown guard window stays hidden", not user32.IsWindowVisible(hwnd), str(hwnd))
    user32.SendMessageW(hwnd, system.WM_QUERYENDSESSION, 0, 0)
    check("WM_QUERYENDSESSION invokes the restore callback", seen == ["queryendsession"], str(seen))
    user32.SendMessageW(hwnd, system.WM_ENDSESSION, 1, 0)
    check("WM_ENDSESSION invokes the restore callback", seen[-1:] == ["endsession"], str(seen))


def test_release_notes() -> None:
    from ai_audit import __version__
    from ai_audit.release_notes import notes_for_version

    text = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    notes = notes_for_version(text, __version__)
    check("changelog provides notes for the current version", len(notes) > 40, notes[:120])
    check("notes stop before the next version heading", "## v" not in notes)
    check("unknown version yields empty notes", notes_for_version(text, "9.9.9") == "")


def run() -> None:
    print("\nEgressScope proxy recovery test")
    print("==============================")
    test_endpoint_matching()
    test_recover_stale()
    test_reconcile()
    test_guard_script()
    test_windows_task_registration()
    test_guard_status()
    test_autostart()
    test_config_hot_reload()
    test_shutdown_hook()
    test_release_notes()
    print("\n==============================")
    print(f"{len(PASSED)} passed, {len(FAILED)} failed")
    if FAILED:
        for name in FAILED:
            print("  - " + name)
        raise SystemExit(1)


if __name__ == "__main__":
    run()
