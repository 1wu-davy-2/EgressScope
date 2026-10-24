from __future__ import annotations

import argparse
import json
import logging
import logging.handlers
import os
import signal
import sys
import threading
import time
import traceback
import webbrowser
from pathlib import Path
from typing import Any

from ai_audit import APP_NAME, __version__
from ai_audit.attribution import ProcessResolver
from ai_audit.config import ConfigStore
from ai_audit.crypto import SecureBox
from ai_audit.fileguard import FileGuard, create_canary_files, remove_canary_files
from ai_audit.paths import AppPaths
from ai_audit.policy import PolicyEngine
from ai_audit.proxy import ProxyController
from ai_audit.store import Store
from ai_audit import system
from ai_audit.web import WebServer

log = logging.getLogger("egressscope")


class EgressApp:
    def __init__(self, paths: AppPaths) -> None:
        self.paths = paths
        self.paths.ensure()
        self.config = ConfigStore(paths.config)
        self.settings = self.config.settings
        self.box = SecureBox(paths.secret)
        self.store = Store(paths.db, self.box)
        self.policy = PolicyEngine(self.settings)
        self.resolver = ProcessResolver(self.settings.listen_port)
        self.proxy = ProxyController(self)
        self.fileguard = FileGuard(self)
        self.web = WebServer(self)
        self.listen_port = 0
        self.web_port = 0
        self.started_at = time.time()
        self.startup_error = ""
        self._stop = threading.Event()
        self._shutdown_done = False
        self._ca_cache: tuple[float, dict, bool] = (0.0, {}, False)
        self._chain_cache: tuple[float, dict] = (0.0, {})
        self._blocked_count = 0

    # ---------- lifecycle ----------
    def start(self) -> None:
        try:
            purged = self.store.purge_older_than(self.settings.retention_days)
            if purged:
                log.info("purged %s expired flows", purged)
        except Exception:
            log.debug("retention cleanup failed", exc_info=True)
        self.web.start()
        try:
            port = self.proxy.start()
            self.listen_port = port
            reconciled = system.reconcile_system_proxy(self.paths, port)
            if reconciled.get("action") == "repointed":
                log.warning(
                    "system proxy repointed from port %s to %s after restart",
                    reconciled.get("previous_port"),
                    port,
                )
            log.info("system proxy can be enabled for 127.0.0.1:%s", port)
        except Exception as exc:
            self.startup_error = f"{type(exc).__name__}: {exc}"
            log.exception("proxy failed to start")
            try:
                recovered = system.recover_stale_proxy(self.paths, grace_seconds=0)
                if recovered.get("action") == "restored":
                    log.warning("restored the original system proxy because the local proxy did not start")
            except Exception:
                log.exception("failed to restore a stale system proxy after a startup error")
        if self.settings.file_guard_enabled:
            self.fileguard.start()
        if self.settings.canary_enabled:
            try:
                create_canary_files(self.paths, self.store, self.settings.canary_dir)
            except Exception:
                log.exception("failed to create canary files on startup")

    def stop(self, restore_proxy: bool = True) -> None:
        if self._shutdown_done:
            return
        self._shutdown_done = True
        self._stop.set()
        if restore_proxy:
            try:
                backup = system.load_proxy_backup(self.paths)
                if backup and self.listen_port:
                    state = system.proxy_state(self.listen_port)
                    if state.get("ours"):
                        system.restore_system_proxy(self.paths)
                        log.info("system proxy restored on shutdown")
                    else:
                        system.uninstall_proxy_guard(self.paths, disable_only=True)
                        log.warning("system proxy was changed externally; backup preserved at %s", self.paths.proxy_backup)
            except Exception:
                log.exception("failed to restore system proxy")
        try:
            self.fileguard.stop()
        except Exception:
            log.debug("fileguard stop failed", exc_info=True)
        try:
            self.proxy.stop()
        except Exception:
            log.debug("proxy stop failed", exc_info=True)
        try:
            self.web.stop()
        except Exception:
            log.debug("web stop failed", exc_info=True)
        try:
            self.store.close()
        except Exception:
            log.debug("store close failed", exc_info=True)
        log.info("EgressScope stopped")

    def wait(self) -> None:
        while not self._stop.wait(1.0):
            pass

    # ---------- integration hooks ----------
    def note_egress(self, pid: int, name: str = "") -> None:
        self.fileguard.note_egress(pid, name)

    def note_flow_saved(self, flow_id: int, pid: int) -> None:
        self._chain_cache = (0.0, {})
        self.web._chain_cache = (0.0, {})
        try:
            info = self.resolver.info_for_pid(pid)
            self.fileguard.note_egress(pid, info.name if info else "")
        except Exception:
            self.fileguard.note_egress(pid)

    def note_blocked(self) -> None:
        self._blocked_count += 1

    # ---------- settings ----------
    def update_settings(self, patch: dict[str, Any]) -> dict[str, Any]:
        clean: dict[str, Any] = {}
        for key, value in patch.items():
            if key in {"capture_enabled", "blocking_enabled", "store_bodies", "file_guard_enabled", "canary_enabled", "inherit_system_proxy", "onboarded"}:
                clean[key] = bool(value)
            elif key == "block_risk":
                clean[key] = max(1, min(100, int(value)))
            elif key in {"retention_days", "file_guard_interval"}:
                clean[key] = max(1, min(365, int(value))) if key == "retention_days" else max(1.0, min(120.0, float(value)))
            elif key == "upstream_proxy":
                clean[key] = str(value or "").strip()
        was_guard = self.settings.file_guard_enabled
        was_canary = self.settings.canary_enabled
        self.config.update(clean)
        self.fileguard.refresh_watch_paths()
        if self.settings.file_guard_enabled and not was_guard:
            self.fileguard.start()
        elif not self.settings.file_guard_enabled and was_guard:
            self.fileguard.stop()
        canary_result = None
        if self.settings.canary_enabled and not was_canary:
            try:
                canary_result = create_canary_files(self.paths, self.store, self.settings.canary_dir)
            except Exception as exc:
                log.exception("canary creation failed")
                canary_result = {"error": str(exc)}
        elif not self.settings.canary_enabled and was_canary:
            try:
                canary_result = remove_canary_files(self.paths, self.store, self.settings.canary_dir)
            except Exception as exc:
                log.exception("canary removal failed")
                canary_result = {"error": str(exc)}
        self._ca_cache = (0.0, {}, False)
        return {
            "settings": {
                "capture_enabled": self.settings.capture_enabled,
                "blocking_enabled": self.settings.blocking_enabled,
                "block_risk": self.settings.block_risk,
                "store_bodies": self.settings.store_bodies,
                "retention_days": self.settings.retention_days,
                "file_guard_enabled": self.settings.file_guard_enabled,
                "canary_enabled": self.settings.canary_enabled,
                "file_guard_interval": self.settings.file_guard_interval,
                "upstream_proxy": self.settings.upstream_proxy,
                "inherit_system_proxy": self.settings.inherit_system_proxy,
            },
            "canary": canary_result,
        }

    def clear_data(self) -> dict[str, Any]:
        self.store.clear_all()
        if self.settings.canary_enabled:
            try:
                create_canary_files(self.paths, self.store, self.settings.canary_dir)
            except Exception:
                log.exception("failed to re-register canaries after clear")
        self.web._chain_cache = (0.0, {})
        self._chain_cache = (0.0, {})
        return {"cleared": True, "time": time.time()}

    def chain_status(self, force: bool = False) -> dict:
        now = time.time()
        if not force and now - self._chain_cache[0] < 15:
            return self._chain_cache[1]
        try:
            result = self.store.verify_chain()
        except Exception as exc:
            result = {"valid": False, "entries": 0, "error": type(exc).__name__}
        self._chain_cache = (now, result)
        return result

    # ---------- windows actions ----------
    def _ensure_ca(self) -> dict:
        return system.ensure_ca(self.paths.certs)

    def ca_status(self, force: bool = False) -> dict[str, Any]:
        now = time.time()
        if not force and now - self._ca_cache[0] < 15:
            info, installed = self._ca_cache[1], self._ca_cache[2]
            return {**info, "installed": installed}
        try:
            info = system.ca_info(self.paths.ca_cert_pem)
            installed = system.is_ca_installed(info.get("sha1", ""))
        except Exception as exc:
            info = {"exists": False, "error": str(exc)}
            installed = False
        self._ca_cache = (now, info, installed)
        return {**info, "installed": installed}

    def install_ca(self) -> dict:
        self._ensure_ca()
        result = system.install_ca(self.paths.ca_cert_cer)
        self._ca_cache = (0.0, {}, False)
        self.web._ca_cache = (0.0, False)
        return result

    def remove_ca(self) -> dict:
        info = self.ca_status(force=True)
        result = system.remove_ca(info.get("sha1", ""))
        self._ca_cache = (0.0, {}, False)
        self.web._ca_cache = (0.0, False)
        return result

    def enable_system_proxy(self) -> dict:
        if not self.proxy.running or not self.listen_port:
            raise system.SystemControlError("本地代理尚未运行，无法启用系统代理")
        return system.enable_system_proxy(self.paths, self.listen_port)

    def restore_system_proxy(self) -> dict:
        return system.restore_system_proxy(self.paths)

    def install_proxy_guard(self) -> dict:
        return system.install_proxy_guard(self.paths)

    def recover_stale_proxy(self, grace_seconds: float = 0) -> dict:
        return system.recover_stale_proxy(self.paths, grace_seconds=grace_seconds)

    def env_text(self) -> str:
        self._ensure_ca()
        return system.env_snippet(self.listen_port or self.settings.listen_port, self.paths.ca_cert_pem)

    def write_env_script(self) -> Path:
        self._ensure_ca()
        return system.write_agent_env(self.paths, self.listen_port or self.settings.listen_port)

    def export_evidence(self, target: Path | None = None) -> dict:
        if target is None:
            stamp = time.strftime("%Y%m%d-%H%M%S")
            target = self.paths.exports / f"egressscope-{stamp}.jsonl"
        return self.store.export_jsonl(Path(target))

    def open_dashboard(self) -> None:
        webbrowser.open(self.web.url)

    def open_data_dir(self) -> None:
        if sys.platform == "win32":
            os.startfile(self.paths.data)  # type: ignore[attr-defined]
        else:
            webbrowser.open(self.paths.data.as_uri())

    # ---------- UI status ----------
    def status_snapshot(self) -> dict[str, Any]:
        ca = self.ca_status()
        state = system.proxy_state(self.listen_port)
        backup = system.load_proxy_backup(self.paths)
        return {
            "proxy_running": self.proxy.running and not self.startup_error,
            "proxy_error": self.startup_error or self.proxy.error,
            "listen_port": self.listen_port,
            "proxy_url": f"http://127.0.0.1:{self.listen_port}" if self.listen_port else "",
            "upstream_proxy": self.proxy.upstream_proxy,
            "upstream_source": self.proxy.upstream_source,
            "web_url": self.web.url if self.web.port else "",
            "capture_enabled": self.settings.capture_enabled,
            "blocking_enabled": self.settings.blocking_enabled,
            "ca_installed": ca.get("installed", False),
            "ca_cn": ca.get("common_name", ""),
            "ca_expires": ca.get("expires_at", ""),
            "system_proxy": state,
            "proxy_backup": bool(backup),
            "proxy_guard": system.proxy_guard_status(self.paths),
            "fileguard": self.fileguard.status(),
            "chain": self.chain_status(),
            "blocked_count": self._blocked_count,
            "version": __version__,
            "uptime": int(time.time() - self.started_at),
        }


def configure_logging(paths: AppPaths, level: str = "INFO") -> None:
    paths.ensure()
    root = logging.getLogger()
    root.setLevel(getattr(logging, level.upper(), logging.INFO))
    for handler in list(root.handlers):
        root.removeHandler(handler)
    formatter = logging.Formatter("%(asctime)s %(levelname)-7s %(name)s: %(message)s", "%Y-%m-%d %H:%M:%S")
    file_handler = logging.handlers.RotatingFileHandler(
        paths.logs / "egressscope.log", maxBytes=2_000_000, backupCount=3, encoding="utf-8"
    )
    file_handler.setFormatter(formatter)
    root.addHandler(file_handler)
    if sys.stderr is not None:
        console = logging.StreamHandler()
        console.setFormatter(formatter)
        root.addHandler(console)
    logging.getLogger("mitmproxy").setLevel(logging.WARNING)
    logging.getLogger("asyncio").setLevel(logging.WARNING)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="EgressScope",
        description="Local data-egress audit for AI agents and desktop applications.",
    )
    parser.add_argument("--headless", action="store_true", help="run without the desktop control window")
    parser.add_argument("--home", type=str, default="", help="override data directory")
    parser.add_argument("--proxy-port", type=int, default=0, help="local proxy port (default 8899)")
    parser.add_argument("--web-port", type=int, default=0, help="dashboard port (default 8898)")
    parser.add_argument("--upstream-ca", type=str, default="", help="extra PEM CA used to verify upstream TLS (testing)")
    parser.add_argument(
        "--insecure-upstream",
        action="store_true",
        help="DANGER: disable upstream TLS verification (testing only)",
    )
    parser.add_argument("--no-fileguard", action="store_true", help="disable the file-handle guard beta")
    parser.add_argument("--upstream-proxy", default="", help="chain through an HTTP/HTTPS proxy, e.g. http://127.0.0.1:7890")
    parser.add_argument("--no-inherit-upstream", action="store_true", help="do not inherit the current loopback system proxy")
    parser.add_argument("--open", action="store_true", help="open the dashboard in the default browser")
    parser.add_argument("--restore-proxy", action="store_true", help="restore the Windows system proxy saved by EgressScope, then exit")
    parser.add_argument("--recover-proxy", action="store_true", help="restore a stale EgressScope system proxy if its port is not listening, then exit")
    parser.add_argument("--recover-grace", type=float, default=0.0, help="seconds to wait for the local proxy before restoring (--recover-proxy)")
    parser.add_argument("--autostart", action="store_true", help="start minimized (used by the logon task)")
    parser.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    parser.add_argument("--version", action="version", version=f"EgressScope {__version__}")
    return parser.parse_args(argv)


def _show_recovery_message(ok: bool, text: str) -> None:
    if sys.platform != "win32":
        return
    try:
        import ctypes

        ctypes.windll.user32.MessageBoxW(None, text, "EgressScope · 系统代理恢复", 0x40 if ok else 0x10)
    except Exception:
        pass


def _run_recovery(args: argparse.Namespace, paths: AppPaths) -> int:
    try:
        if args.restore_proxy:
            result = system.restore_system_proxy(paths)
            text = (
                "系统代理已恢复为 EgressScope 启用前的设置。\n"
                "断网保护计划任务已移除。\n\n"
                "如果浏览器仍未恢复，请重新打开浏览器，或在 Windows 设置 → 网络和 Internet → 代理 中确认。"
            )
        else:
            result = system.recover_stale_proxy(paths, grace_seconds=max(0.0, float(args.recover_grace)))
            action = result.get("action")
            if action == "restored":
                text = f"检测到 127.0.0.1:{result.get('port')} 已停止监听，系统代理已自动恢复。"
            elif result.get("reason") == "healthy":
                text = "本地代理仍在监听，系统代理无需恢复。"
            elif result.get("reason") == "no-backup":
                text = "没有找到 EgressScope 的代理备份，未修改系统设置。"
            elif result.get("reason") == "not-managed":
                text = "当前系统代理未被 EgressScope 管理，未修改系统设置。"
            else:
                text = "检查完成，系统代理无需修改。"
        log.info("proxy recovery result: %s", json.dumps(result, ensure_ascii=False, default=str))
        print(json.dumps(result, ensure_ascii=False, indent=2, default=str))
        if not args.headless:
            _show_recovery_message(True, text)
        return 0
    except Exception as exc:
        log.exception("proxy recovery failed")
        message = f"恢复系统代理失败：{exc}\n\n可手动在 Windows 设置 → 网络和 Internet → 代理 中关闭手动代理。"
        print(message, file=sys.stderr)
        if not args.headless:
            _show_recovery_message(False, message)
        return 1


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    home = Path(args.home) if args.home else None
    paths = AppPaths(home)
    configure_logging(paths, args.log_level)
    log.info("starting %s %s (data dir: %s)", APP_NAME, __version__, paths.data)
    log.info("only use this tool on devices you own or are explicitly authorized to audit")
    if args.restore_proxy or args.recover_proxy:
        return _run_recovery(args, paths)
    try:
        app = EgressApp(paths)
    except Exception:
        log.exception("initialization failed")
        print("EgressScope failed to initialize. See log:", paths.logs / "egressscope.log", file=sys.stderr)
        return 1
    if args.proxy_port:
        app.settings.listen_port = max(1024, min(65535, int(args.proxy_port)))
    if args.web_port:
        app.settings.web_port = max(1024, min(65535, int(args.web_port)))
    if args.upstream_ca:
        app.settings.upstream_ca = args.upstream_ca
    if args.insecure_upstream:
        app.settings.insecure_upstream = True
        app.settings.upstream_ca = ""
    if args.no_fileguard:
        app.settings.file_guard_enabled = False
    if args.upstream_proxy:
        app.settings.upstream_proxy = args.upstream_proxy
    if args.no_inherit_upstream:
        app.settings.inherit_system_proxy = False
    app.settings.normalized()
    app.start()
    if args.open:
        app.open_dashboard()

    def _signal(_signum, _frame):
        app.stop()

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            signal.signal(sig, _signal)
        except (ValueError, OSError):
            pass

    if args.headless:
        print(f"EgressScope dashboard: {app.web.url}")
        print(f"Local proxy: http://127.0.0.1:{app.listen_port or app.settings.listen_port}")
        print(f"CA certificate: {paths.ca_cert_pem}")
        if app.startup_error:
            print("Proxy error:", app.startup_error, file=sys.stderr)
        try:
            app.wait()
        except KeyboardInterrupt:
            pass
        finally:
            app.stop()
        return 0 if not app.startup_error else 2

    try:
        from ai_audit.ui import ControlWindow

        window = ControlWindow(app)
        if args.autostart:
            window.start_minimized()
        window.run()
    except Exception:
        log.exception("desktop UI failed; falling back to headless mode")
        try:
            app.wait()
        except KeyboardInterrupt:
            pass
    finally:
        app.stop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
