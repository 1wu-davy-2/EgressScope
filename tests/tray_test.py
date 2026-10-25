"""Hermetic tests for the Windows notification-area controller.

No real tray icon, pystray backend, or GUI window is created. pystray is
replaced by a fake module whose icon loop blocks until stop() is called.
Run from the project root:

    python tests/tray_test.py
"""
from __future__ import annotations

import ast
import inspect
import sys
import threading
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ai_audit import tray

PASSED: list[str] = []
FAILED: list[str] = []


def check(name: str, condition: bool, detail: str = "") -> None:
    if condition:
        PASSED.append(name)
        print(f"  PASS  {name}")
    else:
        FAILED.append(name)
        print(f"  FAIL  {name}{(' — ' + detail) if detail else ''}")


# ---------- fakes ----------
class FakeMenuItem:
    def __init__(self, text, action, checked=None, radio=False, default=False, visible=True, enabled=True) -> None:
        self._text = text
        self.action = action
        self._default = default

    @property
    def text(self) -> str:
        return self._text(self) if callable(self._text) else self._text

    @property
    def default(self) -> bool:
        return self._default


class FakeMenu:
    def __init__(self, *items) -> None:
        self.items = list(items)


class FakeIcon:
    def __init__(self, name, icon, title=None, menu=None) -> None:
        self.name = name
        self._icon = icon
        self.icon_updates: list[object] = []
        self._title = title or ""
        self.title_updates: list[str] = [title or ""]
        self.menu = menu
        self.notifications: list[tuple[str, str]] = []
        self.visible = False
        self.stopped = False
        self.started = threading.Event()
        self._stop_event = threading.Event()

    @property
    def icon(self):
        return self._icon

    @icon.setter
    def icon(self, value) -> None:
        self._icon = value
        self.icon_updates.append(value)

    @property
    def title(self) -> str:
        return self._title

    @title.setter
    def title(self, value: str) -> None:
        if value != self._title:
            self._title = value
            self.title_updates.append(value)

    def run(self) -> None:
        self.visible = True
        self.started.set()
        self._stop_event.wait(5.0)
        self.visible = False

    def stop(self) -> None:
        self.stopped = True
        self._stop_event.set()

    def notify(self, message: str, title: str | None = None) -> None:
        self.notifications.append((title or "", message))

    def update_menu(self) -> None:
        return


class FakePystray:
    def __init__(self, broken: bool = False) -> None:
        self.icons: list[FakeIcon] = []
        self.broken = broken
        self.Menu = FakeMenu
        self.MenuItem = FakeMenuItem

    def Icon(self, *args, **kwargs):
        if self.broken:
            raise RuntimeError("icon construction failed")
        icon = FakeIcon(*args, **kwargs)
        self.icons.append(icon)
        return icon


class FakeApp:
    def __init__(self, capture_enabled: bool = True) -> None:
        self.settings = SimpleNamespace(capture_enabled=capture_enabled)
        self.update_calls: list[dict] = []
        self.dashboard_calls = 0

    def update_settings(self, patch: dict) -> dict:
        self.update_calls.append(dict(patch))
        if "capture_enabled" in patch:
            self.settings.capture_enabled = bool(patch["capture_enabled"])
        return {"changed": sorted(patch)}

    def open_dashboard(self) -> None:
        self.dashboard_calls += 1


class FakeImage:
    """Stand-in for a PIL image so lifecycle tests do not require Pillow."""

    def __init__(self, paused: bool) -> None:
        self.paused = paused


def patched_pystray(fake: FakePystray):
    original = tray._import_pystray
    tray._import_pystray = lambda: fake
    return original


def make_controller(
    app: FakeApp,
    events: dict[str, int],
    platform: str = "win32",
    show_dashboard=None,
) -> tray.TrayController:
    def count(key: str):
        def bump() -> None:
            events[key] += 1

        return bump

    return tray.TrayController(
        app,
        show_window=count("show"),
        refresh=count("refresh"),
        quit_app=count("quit"),
        platform=platform,
        show_dashboard=show_dashboard,
    )


def make_started(fake: FakePystray, capture: bool = True, show_dashboard=None):
    original = patched_pystray(fake)
    original_image = tray.make_icon_image
    tray.make_icon_image = lambda paused=False: FakeImage(paused)
    app = FakeApp(capture)
    events = {"show": 0, "refresh": 0, "quit": 0}
    controller = make_controller(app, events, show_dashboard=show_dashboard)
    started = controller.start()
    if started:
        fake.icons[0].started.wait(1.0)
    return original, original_image, controller, app, events


def stop_and_restore(controller, original, original_image) -> None:
    controller.stop()
    tray._import_pystray = original
    tray.make_icon_image = original_image


# ---------- tests ----------
def test_platform_and_close_behavior() -> None:
    print("\nplatform gate and close behavior")
    check("tray is supported on win32", tray.supported("win32") is True)
    check("tray is not supported on linux", tray.supported("linux") is False)
    check("tray is not supported on darwin", tray.supported("darwin") is False)
    check("supported() defaults to sys.platform", tray.supported() == (sys.platform == "win32"))
    check("closing with an active tray hides", tray.close_behavior(True, False) == "tray")
    check("closing while quitting exits", tray.close_behavior(True, True) == "exit")
    check("closing without a tray exits", tray.close_behavior(False, False) == "exit")
    check("closing without a tray while quitting exits", tray.close_behavior(False, True) == "exit")


def color_count(image, rgb: tuple[int, int, int]) -> int:
    counts = image.getcolors(maxcolors=image.width * image.height) or []
    for count, color in counts:
        if color[:3] == rgb and color[3] == 255:
            return count
    return 0


def test_icon_image() -> None:
    print("\ntray icon rendering")
    active_rgb = tuple(int(tray.COLOR_ACTIVE[index:index + 2], 16) for index in (1, 3, 5))
    paused_rgb = tuple(int(tray.COLOR_PAUSED[index:index + 2], 16) for index in (1, 3, 5))
    active = tray.make_icon_image(False)
    paused = tray.make_icon_image(True)
    if active is None or paused is None:
        print("  SKIP  Pillow is unavailable; icon rendering checks skipped")
        return
    check("icon is a 64x64 RGBA image", active.size == (64, 64) and active.mode == "RGBA", str((active.size, active.mode)))
    check("icon background is transparent", active.getpixel((0, 0))[3] == 0)
    check("active icon draws mint rings", color_count(active, active_rgb) > 0)
    check("paused icon draws slate rings", color_count(paused, paused_rgb) > 0)
    check("paused icon drops the mint rings", color_count(paused, active_rgb) == 0)
    check("active and paused icons differ", active.tobytes() != paused.tobytes())


def test_start_failures() -> None:
    print("\nstart failures stay silent and return False")
    fake = FakePystray()
    original = patched_pystray(fake)
    original_image = tray.make_icon_image
    try:
        app = FakeApp()
        events = {"show": 0, "refresh": 0, "quit": 0}
        non_windows = make_controller(app, events, platform="linux")
        result = non_windows.start()
        check("non-Windows start returns False", result is False)
        check("non-Windows start stays inactive", non_windows.active is False)
        check("non-Windows start creates no icon", not fake.icons)

        broken_import = tray.TrayController(
            app,
            show_window=lambda: None,
            refresh=lambda: None,
            quit_app=lambda: None,
            platform="win32",
        )
        tray._import_pystray = lambda: (_ for _ in ()).throw(ImportError("pystray missing"))
        result = broken_import.start()
        check("missing pystray returns False without raising", result is False)
        check("missing pystray stays inactive", broken_import.active is False)

        tray._import_pystray = lambda: fake
        tray.make_icon_image = lambda paused=False: None
        missing_image = make_controller(app, events)
        result = missing_image.start()
        check("missing Pillow returns False without raising", result is False)
        check("missing Pillow stays inactive", missing_image.active is False)
        check("missing Pillow creates no icon", not fake.icons)

        tray.make_icon_image = lambda paused=False: FakeImage(paused)
        broken_icon_fake = FakePystray(broken=True)
        tray._import_pystray = lambda: broken_icon_fake
        broken_icon = make_controller(app, events)
        result = broken_icon.start()
        check("icon construction failure returns False", result is False)
        check("icon construction failure stays inactive", broken_icon.active is False)
        check("icon construction failure creates no icon", not broken_icon_fake.icons)
        broken_icon.stop()
        missing_image.stop()
        broken_import.stop()
        non_windows.stop()
    finally:
        tray._import_pystray = original
        tray.make_icon_image = original_image


def test_start_stop() -> None:
    print("\nstart and idempotent stop")
    fake = FakePystray()
    original, original_image, controller, app, events = make_started(fake)
    try:
        icon = fake.icons[0]
        check("start on win32 with pystray becomes active", controller.active is True)
        check("start creates exactly one icon", len(fake.icons) == 1)
        check("icon loop is running", icon.started.wait(1.0) is True)
        check("initial tooltip is branded", icon.title == "EgressScope · 本机数据外发审计", icon.title)
        controller.stop()
        check("stop deactivates the controller", controller.active is False)
        check("stop stops the icon loop", icon.stopped is True)
        controller.stop()
        check("stop is idempotent", controller.active is False)
        never_started = make_controller(FakeApp(), {"show": 0, "refresh": 0, "quit": 0})
        never_started.stop()
        check("stop before start is safe", never_started.active is False)
    finally:
        stop_and_restore(controller, original, original_image)


def test_menu_and_capture_toggle() -> None:
    print("\nmenu labels, callbacks, and capture toggle")
    fake = FakePystray()
    original, original_image, controller, app, events = make_started(fake)
    try:
        icon = fake.icons[0]
        menu = icon.menu
        check("menu contains four items", len(menu.items) == 4, str(len(menu.items)))
        check("console item is first and default", menu.items[0].text == "打开控制台" and menu.items[0].default is True)
        check("dashboard item is present", menu.items[1].text == "打开审计仪表盘")
        check("capture item starts as pause", menu.items[2].text == "暂停审计")
        check("quit item is present", menu.items[3].text == "退出并恢复系统代理")

        menu.items[0].action()
        check("console action shows the window", events["show"] == 1)
        menu.items[1].action()
        check("dashboard action opens the dashboard", app.dashboard_calls == 1)
        menu.items[3].action()
        check("quit action invokes the quit callback", events["quit"] == 1)

        initial_image = icon.icon
        menu.items[2].action()
        check("pause calls update_settings with the inverse value", app.update_calls == [{"capture_enabled": False}], str(app.update_calls))
        check("pause updates the app setting", app.settings.capture_enabled is False)
        check("pause updates the tooltip", icon.title.endswith(" · 已暂停"), icon.title)
        check("pause replaces the icon image", icon.icon is not initial_image)
        check("pause label becomes resume", menu.items[2].text == "恢复审计")
        check("pause invokes the refresh callback", events["refresh"] == 1)

        menu.items[2].action()
        check("resume calls update_settings with the inverse value", app.update_calls[-1] == {"capture_enabled": True}, str(app.update_calls))
        check("resume restores the tooltip", not icon.title.endswith(" · 已暂停"), icon.title)
        check("resume label becomes pause", menu.items[2].text == "暂停审计")
        check("resume invokes the refresh callback", events["refresh"] == 2)
    finally:
        stop_and_restore(controller, original, original_image)


def test_injected_dashboard_callback() -> None:
    print("\ninjected dashboard callback")
    fake = FakePystray()
    calls = {"dashboard": 0}

    def dashboard() -> None:
        calls["dashboard"] += 1

    original, original_image, controller, app, events = make_started(fake, show_dashboard=dashboard)
    try:
        fake.icons[0].menu.items[1].action()
        check("dashboard uses the injected callback", calls["dashboard"] == 1)
        check("injected dashboard does not fall back to app.open_dashboard", app.dashboard_calls == 0)
    finally:
        stop_and_restore(controller, original, original_image)


def test_notify_hidden() -> None:
    print("\nhide notification")
    fake = FakePystray()
    original, original_image, controller, app, events = make_started(fake)
    try:
        icon = fake.icons[0]
        controller.notify_hidden()
        controller.notify_hidden()
        check("notify_hidden notifies only once", len(icon.notifications) == 1, str(len(icon.notifications)))
        message = icon.notifications[0][1] if icon.notifications else ""
        check("notification explains the app keeps running", "仍在后台运行" in message, message)
        check("notification explains exit restores the proxy", "恢复系统代理" in message, message)
    finally:
        stop_and_restore(controller, original, original_image)

    fake2 = FakePystray()
    original2, original_image2, controller2, app2, events2 = make_started(fake2)
    try:
        def explode(message, title=None):
            raise RuntimeError("balloon unavailable")

        fake2.icons[0].notify = explode
        try:
            controller2.notify_hidden()
            raised = False
        except Exception:
            raised = True
        check("notification failures are wrapped", raised is False)
    finally:
        stop_and_restore(controller2, original2, original_image2)


def test_sync_external_change() -> None:
    print("\nsync picks up external capture changes")
    fake = FakePystray()
    original, original_image, controller, app, events = make_started(fake, capture=True)
    try:
        icon = fake.icons[0]
        menu = icon.menu
        initial_image = icon.icon
        initial_title_updates = len(icon.title_updates)
        app.settings.capture_enabled = False
        controller.sync()
        check("sync detects an external pause", icon.title.endswith(" · 已暂停"), icon.title)
        check("sync replaces the icon image", icon.icon is not initial_image)
        check("sync refreshes the dynamic menu label", menu.items[2].text == "恢复审计")
        check("sync updates the title only on change", len(icon.title_updates) == initial_title_updates + 1)

        unchanged_image = icon.icon
        unchanged_titles = len(icon.title_updates)
        controller.sync()
        check("sync is a no-op when the state is unchanged", icon.icon is unchanged_image and len(icon.title_updates) == unchanged_titles)

        app.settings.capture_enabled = True
        controller.sync()
        check("sync detects an external resume", not icon.title.endswith(" · 已暂停") and menu.items[2].text == "暂停审计")
    finally:
        stop_and_restore(controller, original, original_image)


def test_cli_and_lazy_import() -> None:
    print("\nCLI flag and lazy import")
    from app import parse_args

    check("--no-tray parses to True", parse_args(["--no-tray"]).no_tray is True)
    check("--no-tray defaults to False", parse_args([]).no_tray is False)
    check("_import_pystray is a function", inspect.isfunction(tray._import_pystray))

    source = Path(tray.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    imported: list[str] = []
    for node in tree.body:
        if isinstance(node, ast.Import):
            imported.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                imported.append(node.module)
            imported.extend(alias.name for alias in node.names)
    eager = [name for name in imported if name.startswith(("pystray", "PIL"))]
    check("module import does not require pystray or PIL", not eager, str(eager))


def run() -> None:
    print("\nEgressScope notification-area test")
    print("=================================")
    test_platform_and_close_behavior()
    test_icon_image()
    test_start_failures()
    test_start_stop()
    test_menu_and_capture_toggle()
    test_injected_dashboard_callback()
    test_notify_hidden()
    test_sync_external_change()
    test_cli_and_lazy_import()
    print("\n=================================")
    print(f"{len(PASSED)} passed, {len(FAILED)} failed")
    if FAILED:
        for name in FAILED:
            print("  - " + name)
        raise SystemExit(1)


if __name__ == "__main__":
    run()
