"""Windows notification-area (tray) support for the control window.

Importing this module is always safe: pystray and Pillow are optional and are
only imported when a tray is actually requested. When the platform is not
Windows or the dependencies are unavailable, :meth:`TrayController.start`
returns ``False`` and the caller keeps the existing close-means-exit behavior.

All Tk interaction stays in :mod:`ai_audit.ui`; callbacks injected here may be
invoked from the pystray thread and must marshal themselves onto the Tk thread.
"""
from __future__ import annotations

import logging
import sys
import threading
from typing import Any, Callable

log = logging.getLogger(__name__)

ICON_TITLE = "EgressScope · 本机数据外发审计"
ICON_SIZE = 64
COLOR_ACTIVE = "#36e6c2"
COLOR_PAUSED = "#8294a8"

MENU_OPEN_CONSOLE = "打开控制台"
MENU_OPEN_DASHBOARD = "打开审计仪表盘"
MENU_PAUSE = "暂停审计"
MENU_RESUME = "恢复审计"
MENU_QUIT = "退出并恢复系统代理"

HIDDEN_MESSAGE = (
    "EgressScope 仍在后台运行。"
    "右键托盘图标可打开控制台、查看审计仪表盘或暂停审计；"
    "选择“退出并恢复系统代理”可完全退出并还原系统代理设置。"
)


def supported(platform: str | None = None) -> bool:
    """Whether the notification area is supported on *platform*."""
    current = sys.platform if platform is None else platform
    return current == "win32"


def _import_pystray():
    """Import pystray lazily so the module stays importable without it."""
    import pystray  # noqa: PLC0415 - deliberately lazy

    return pystray


def make_icon_image(paused: bool = False):
    """Render the 64x64 RGBA tray icon, or return None if Pillow is missing."""
    try:
        from PIL import Image, ImageDraw
    except Exception:
        log.warning("Pillow is not available; the notification-area icon cannot be rendered")
        return None
    color = COLOR_PAUSED if paused else COLOR_ACTIVE
    image = Image.new("RGBA", (ICON_SIZE, ICON_SIZE), (0, 0, 0, 0))
    draw = ImageDraw.Draw(image)
    # Concentric rings around a solid core, echoing the control-window logo.
    for inset, width in ((4, 3), (14, 3), (24, 3)):
        draw.ellipse(
            (inset, inset, ICON_SIZE - 1 - inset, ICON_SIZE - 1 - inset),
            outline=color,
            width=width,
        )
    draw.ellipse((30, 30, 33, 33), fill=color)
    return image


def close_behavior(tray_active: bool, quitting: bool) -> str:
    """Return ``"tray"`` when closing should hide, else ``"exit"``."""
    return "tray" if tray_active and not quitting else "exit"


class TrayController:
    """Own the pystray icon and translate menu actions into app callbacks."""

    def __init__(
        self,
        app: Any,
        show_window: Callable[[], None],
        refresh: Callable[[], None],
        quit_app: Callable[[], None],
        platform: str | None = None,
        show_dashboard: Callable[[], None] | None = None,
    ) -> None:
        self.app = app
        self._show_window = show_window
        self._refresh = refresh
        self._quit_app = quit_app
        self._show_dashboard = show_dashboard or getattr(app, "open_dashboard", None)
        self._platform = sys.platform if platform is None else platform
        self._lock = threading.RLock()
        self._pystray: Any = None
        self._icon: Any = None
        self._thread: threading.Thread | None = None
        self._active = False
        self._paused: bool | None = None
        self._notified = False

    # ---------- lifecycle ----------
    @property
    def active(self) -> bool:
        return self._active

    def start(self) -> bool:
        """Create and run the tray icon. Returns False with a warning on failure."""
        with self._lock:
            if self._active:
                return True
        if not supported(self._platform):
            log.warning("notification area is only available on Windows; the tray is disabled")
            return False
        try:
            pystray = _import_pystray()
        except Exception:
            log.warning("pystray is not available; the notification-area icon is disabled")
            return False
        paused = self._paused_state()
        try:
            image = make_icon_image(paused=paused)
        except Exception:
            log.warning("failed to render the notification-area icon; the tray is disabled", exc_info=True)
            return False
        if image is None:
            log.warning("the notification-area icon image is unavailable; the tray is disabled")
            return False
        try:
            menu = pystray.Menu(
                pystray.MenuItem(MENU_OPEN_CONSOLE, self._on_open_console, default=True),
                pystray.MenuItem(MENU_OPEN_DASHBOARD, self._on_open_dashboard),
                pystray.MenuItem(self._capture_label, self._on_toggle_capture),
                pystray.MenuItem(MENU_QUIT, self._on_quit),
            )
            icon = pystray.Icon("egressscope", image, self._tooltip(paused), menu)
        except Exception:
            log.warning("failed to construct the notification-area icon; the tray is disabled", exc_info=True)
            return False
        thread = threading.Thread(
            target=self._run_icon,
            args=(icon,),
            name="egressscope-tray",
            daemon=True,
        )
        with self._lock:
            self._pystray = pystray
            self._icon = icon
            self._thread = thread
            self._paused = paused
            self._active = True
        try:
            thread.start()
        except Exception:
            log.warning("failed to start the notification-area icon thread", exc_info=True)
            with self._lock:
                self._icon = None
                self._thread = None
                self._pystray = None
                self._active = False
            return False
        log.info("notification-area icon started")
        return True

    def _run_icon(self, icon: Any) -> None:
        try:
            icon.run()
        except Exception:
            log.exception("notification-area icon loop stopped unexpectedly")
        finally:
            with self._lock:
                if self._icon is icon:
                    self._active = False
                    self._icon = None
                    self._thread = None

    def stop(self) -> None:
        """Stop the icon loop; safe to call more than once."""
        with self._lock:
            icon = self._icon
            thread = self._thread
            self._icon = None
            self._thread = None
            self._active = False
        if icon is not None:
            try:
                icon.stop()
            except Exception:
                log.debug("notification-area icon stop failed", exc_info=True)
        if thread is not None and thread.is_alive() and thread is not threading.current_thread():
            thread.join(timeout=2.0)

    # ---------- state ----------
    def _capture_enabled(self) -> bool:
        try:
            return bool(getattr(self.app.settings, "capture_enabled", True))
        except Exception:
            return True

    def _paused_state(self) -> bool:
        return not self._capture_enabled()

    @staticmethod
    def _tooltip(paused: bool) -> str:
        return ICON_TITLE + (" · 已暂停" if paused else "")

    def sync(self) -> None:
        """Apply an externally changed capture state; cheap to call periodically."""
        if not self._active:
            return
        self._apply_state(force=False)

    def _apply_state(self, force: bool) -> None:
        paused = self._paused_state()
        with self._lock:
            changed = paused != self._paused
            if not changed and not force:
                return
            self._paused = paused
            icon = self._icon
        if icon is None:
            return
        try:
            image = make_icon_image(paused=paused)
            if image is not None:
                icon.icon = image
            icon.title = self._tooltip(paused)
            update_menu = getattr(icon, "update_menu", None)
            if callable(update_menu):
                update_menu()
        except Exception:
            log.debug("failed to update the notification-area icon", exc_info=True)

    # ---------- notifications ----------
    def notify_hidden(self) -> None:
        """Explain the first hide per session; later calls are no-ops."""
        with self._lock:
            if self._notified:
                return
            self._notified = True
            icon = self._icon
        if icon is None:
            return
        try:
            icon.notify(HIDDEN_MESSAGE, ICON_TITLE)
        except Exception:
            log.debug("notification-area balloon could not be shown", exc_info=True)

    # ---------- menu ----------
    def _capture_label(self, item: Any = None) -> str:
        return MENU_RESUME if self._paused_state() else MENU_PAUSE

    def _call(self, callback: Callable[[], None] | None, name: str) -> None:
        if callback is None:
            log.warning("notification-area action %s has no callback", name)
            return
        try:
            callback()
        except Exception:
            log.debug("notification-area action %s failed", name, exc_info=True)

    def _on_open_console(self, icon: Any = None, item: Any = None) -> None:
        self._call(self._show_window, "open-console")

    def _on_open_dashboard(self, icon: Any = None, item: Any = None) -> None:
        self._call(self._show_dashboard, "open-dashboard")

    def _on_toggle_capture(self, icon: Any = None, item: Any = None) -> None:
        desired = not self._capture_enabled()
        try:
            self.app.update_settings({"capture_enabled": desired})
        except Exception:
            log.exception("failed to toggle capture from the notification area")
        self._apply_state(force=True)
        self._call(self._refresh, "refresh")

    def _on_quit(self, icon: Any = None, item: Any = None) -> None:
        self._call(self._quit_app, "quit")
