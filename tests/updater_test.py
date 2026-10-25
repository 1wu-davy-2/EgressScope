"""Focused tests for GitHub update checking and verified downloads.

All network and process creation is mocked. Run from the project root:

    python tests/updater_test.py
"""
from __future__ import annotations

import contextlib
import hashlib
import io
import json
import sys
import tempfile
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ai_audit import updater
from ai_audit.config import EDITABLE_KEYS, ConfigStore, Settings

PASSED: list[str] = []
FAILED: list[str] = []

ASSET_NAME = "EgressScope-Setup-v0.4.0.exe"
ASSET_URL = f"https://github.com/1wu-davy-2/EgressScope/releases/download/v0.4.0/{ASSET_NAME}"
SHA_URL = ASSET_URL + ".sha256"
SUMS_URL = "https://github.com/1wu-davy-2/EgressScope/releases/download/v0.4.0/SHA256SUMS.txt"


def check(name: str, condition: bool, detail: str = "") -> None:
    if condition:
        PASSED.append(name)
        print(f"  PASS  {name}")
    else:
        FAILED.append(name)
        print(f"  FAIL  {name}{(' — ' + detail) if detail else ''}")


class FakeResponse:
    def __init__(self, body: bytes, url: str) -> None:
        self._body = body
        self._offset = 0
        self._url = url
        self.headers = {"Content-Length": str(len(body))}

    def read(self, size: int = -1) -> bytes:
        if size is None or size < 0:
            size = len(self._body) - self._offset
        chunk = self._body[self._offset:self._offset + size]
        self._offset += len(chunk)
        return chunk

    def geturl(self) -> str:
        return self._url

    def close(self) -> None:
        pass


def release_payload(tag: str = "v0.4.0", *, prerelease: bool = False, draft: bool = False) -> dict:
    return {
        "tag_name": tag,
        "draft": draft,
        "prerelease": prerelease,
        "published_at": "2026-10-01T12:00:00Z",
        "html_url": "https://github.com/1wu-davy-2/EgressScope/releases/tag/v0.4.0",
        "assets": [
            {
                "name": "EgressScope-Setup-v9.9.9.exe",
                "browser_download_url": "https://github.com/1wu-davy-2/EgressScope/releases/download/v9.9.9/EgressScope-Setup-v9.9.9.exe",
            },
            {"name": ASSET_NAME, "browser_download_url": ASSET_URL},
            {"name": ASSET_NAME + ".sha256", "browser_download_url": SHA_URL},
            {"name": "notes.txt", "browser_download_url": "https://github.com/1wu-davy-2/EgressScope/releases/download/v0.4.0/notes.txt"},
        ],
    }


def check_update(payload: dict, current: str = "0.3.2", *, platform: str = "win32", machine: str = "AMD64") -> dict:
    calls: list[dict] = []

    def fake_open(url, *, timeout, headers=None):
        calls.append({"url": url, "headers": headers or {}, "timeout": timeout})
        return FakeResponse(json.dumps(payload).encode("utf-8"), url)

    with mock.patch.object(updater, "_open_url", side_effect=fake_open), \
         mock.patch.object(updater.sys, "platform", platform), \
         mock.patch.object(updater._platform, "machine", return_value=machine):
        result = updater.check_for_update(current)
        result["_calls"] = calls
    return result


def test_semver() -> None:
    check("numeric versions parse", updater.parse_version("v1.2.3") == (1, 2, 3))
    check("plain versions parse", updater.parse_version("0.4.0") == (0, 4, 0))
    check("invalid versions are rejected", updater.parse_version("1.2") is None and updater.parse_version("") is None)
    check("0.10.0 sorts after 0.9.9", updater.compare_versions("0.10.0", "0.9.9") > 0)
    check("equal versions compare equal", updater.compare_versions("v1.2.3", "1.2.3") == 0)
    check("older versions compare lower", updater.compare_versions("0.3.1", "0.3.2") < 0)


def test_newer_release() -> None:
    info = check_update(release_payload())
    check("new release reports ok", info.get("ok") is True, str(info))
    check("new release is available", info.get("available") is True)
    check("latest numeric version is reported", info.get("latest") == "0.4.0", str(info.get("latest")))
    check("tag is preserved", info.get("tag") == "v0.4.0")
    check("exact setup asset is selected", info.get("asset_name") == ASSET_NAME, str(info.get("asset_name")))
    check("setup download URL is selected", info.get("asset_url") == ASSET_URL)
    check("matching sha256 asset is selected", info.get("sha256_url") == SHA_URL)
    check("release notes URL is reported", str(info.get("notes_url", "")).endswith("/releases/tag/v0.4.0"))
    check("publish time is reported", bool(info.get("published_at")))
    check("windows x64 release is installable", info.get("installable") is True)
    calls = info.get("_calls") or []
    headers = calls[0]["headers"] if calls else {}
    check("API Accept header is set", headers.get("Accept") == "application/vnd.github+json", str(headers))
    check(
        "User-Agent identifies EgressScope and current version",
        "EgressScope" in str(headers.get("User-Agent", "")) and "0.3.2" in str(headers.get("User-Agent", "")),
        str(headers.get("User-Agent")),
    )


def test_no_update() -> None:
    info = check_update(release_payload("v0.3.2"))
    check("same version is not an update", info.get("ok") is True and info.get("available") is False, str(info))
    check("no-update result is not installable", info.get("installable") is False)
    older = check_update(release_payload("v0.3.1"))
    check("older release is not an update", older.get("ok") is True and older.get("available") is False, str(older))
    newer = check_update(release_payload("v0.10.0"), current="0.9.9")
    check("10th minor release is newer than 9.9", newer.get("available") is True, str(newer))


def test_prerelease_ignored() -> None:
    pre = check_update(release_payload("v0.9.0", prerelease=True))
    check("prerelease is ignored", pre.get("ok") is True and pre.get("available") is False, str(pre))
    check("prerelease does not expose a tag", pre.get("tag") == "" and pre.get("latest") == "")
    draft = check_update(release_payload("v0.9.0", draft=True))
    check("draft is ignored", draft.get("ok") is True and draft.get("available") is False, str(draft))


def test_non_windows_not_installable() -> None:
    info = check_update(release_payload(), platform="linux", machine="x86_64")
    check("non-Windows still reports the latest release", info.get("ok") is True and info.get("latest") == "0.4.0")
    check("non-Windows is not installable", info.get("installable") is False, str(info.get("platform")))
    arm = check_update(release_payload(), platform="win32", machine="ARM64")
    check("Windows ARM64 does not offer the x64 setup", arm.get("available") is True and arm.get("installable") is False)


def test_network_failure() -> None:
    with mock.patch.object(updater, "_open_url", side_effect=OSError("offline")), \
         mock.patch.object(updater.sys, "platform", "win32"), \
         mock.patch.object(updater._platform, "machine", return_value="AMD64"):
        info = updater.check_for_update("0.3.2")
    check("network failure is reported as ok=false", info.get("ok") is False, str(info))
    check("network failure keeps available=false", info.get("available") is False)
    check("network failure has a clear error", "offline" in str(info.get("error", "")), str(info.get("error")))


def test_download_and_checksum() -> None:
    content = b"verified setup payload"
    digest = hashlib.sha256(content).hexdigest()
    info = {
        "asset_name": ASSET_NAME,
        "asset_url": ASSET_URL,
        "sha256_url": SHA_URL,
        "latest": "0.4.0",
        "available": True,
        "installable": True,
    }

    def fake_open(url, *, timeout, headers=None):
        if url == SHA_URL:
            return FakeResponse(f"{digest}  {ASSET_NAME}\n".encode("utf-8"), url)
        return FakeResponse(content, url)

    with tempfile.TemporaryDirectory(prefix="egressscope-updater-") as temp, \
         mock.patch.object(updater, "_open_url", side_effect=fake_open):
        target = updater.download_update(info, dest_dir=temp)
        check("download returns the verified setup", target.exists() and target.read_bytes() == content, str(target))
        check("downloaded setup keeps its asset name", target.name == ASSET_NAME)

    def sums_open(url, *, timeout, headers=None):
        if url == SUMS_URL:
            body = (
                f"{'0' * 64}  other-file.exe\n"
                f"{digest}  {ASSET_NAME}\n"
            ).encode("utf-8")
            return FakeResponse(body, url)
        return FakeResponse(content, url)

    sums_info = dict(info, sha256_url=SUMS_URL)
    with tempfile.TemporaryDirectory(prefix="egressscope-updater-sums-") as temp, \
         mock.patch.object(updater, "_open_url", side_effect=sums_open):
        target = updater.download_update(sums_info, dest_dir=temp)
        check("SHA256SUMS.txt fallback verifies the setup", target.exists(), str(target))


def test_release_assets_host() -> None:
    content = b"release asset payload"
    digest = hashlib.sha256(content).hexdigest()
    asset_url = f"https://release-assets.githubusercontent.com/github-production-release-asset/1/{ASSET_NAME}"
    info = {
        "asset_name": ASSET_NAME,
        "asset_url": asset_url,
        "sha256_url": SHA_URL,
        "available": True,
        "installable": True,
    }

    def fake_open(url, *, timeout, headers=None):
        if url == SHA_URL:
            return FakeResponse(f"{digest}  {ASSET_NAME}\n".encode("utf-8"), url)
        return FakeResponse(content, url)

    with tempfile.TemporaryDirectory(prefix="egressscope-release-assets-") as temp, \
         mock.patch.object(updater, "_open_url", side_effect=fake_open):
        target = updater.download_update(info, dest_dir=temp)
        check(
            "GitHub release-assets host is allowed after redirect",
            target.exists() and target.read_bytes() == content,
            str(target),
        )


def test_sha256_mismatch_deletes_file() -> None:
    info = {
        "asset_name": ASSET_NAME,
        "asset_url": ASSET_URL,
        "sha256_url": SHA_URL,
        "available": True,
        "installable": True,
    }

    def fake_open(url, *, timeout, headers=None):
        if url == SHA_URL:
            return FakeResponse(f"{'0' * 64}  {ASSET_NAME}\n".encode("utf-8"), url)
        return FakeResponse(b"tampered payload", url)

    raised = False
    message = ""
    with tempfile.TemporaryDirectory(prefix="egressscope-updater-bad-") as temp, \
         mock.patch.object(updater, "_open_url", side_effect=fake_open):
        try:
            updater.download_update(info, dest_dir=temp)
        except ValueError as exc:
            raised = True
            message = str(exc)
        target = Path(temp) / ASSET_NAME
        check("checksum mismatch raises ValueError", raised and "SHA-256" in message, message)
        check("checksum mismatch deletes the downloaded file", not target.exists(), str(target))


def test_download_host_allowlist() -> None:
    info = {
        "asset_name": ASSET_NAME,
        "asset_url": "https://evil.example/EgressScope-Setup-v0.4.0.exe",
        "sha256_url": SHA_URL,
    }
    called = False

    def fake_open(url, *, timeout, headers=None):
        nonlocal called
        called = True
        return FakeResponse(b"", url)

    with mock.patch.object(updater, "_open_url", side_effect=fake_open):
        try:
            updater.download_update(info)
        except ValueError as exc:
            message = str(exc)
        else:
            message = ""
    check("non-GitHub download host is rejected", "域名" in message, message)
    check("rejected host is never fetched", not called)
    rejected = 0
    for bad in ("http://github.com/1wu-davy-2/EgressScope", "https://github.com.evil.example/x"):
        try:
            updater._require_allowed_url(bad)
        except ValueError:
            rejected += 1
    check("HTTP and lookalike hosts are rejected", rejected == 2, str(rejected))


def test_launch_installer() -> None:
    with tempfile.TemporaryDirectory(prefix="egressscope-setup-") as temp:
        setup = Path(temp) / ASSET_NAME
        setup.write_bytes(b"MZ")
        sentinel = object()
        with mock.patch.object(updater.subprocess, "Popen", return_value=sentinel) as popen:
            result = updater.launch_installer(setup)
        args, kwargs = popen.call_args
        check(
            "installer is launched with silent no-restart flags",
            args[0] == [str(setup), "/SILENT", "/NORESTART", "/CLOSEAPPLICATIONS"],
            str(args[0]),
        )
        check("installer launch does not use a shell", kwargs.get("shell") is False, str(kwargs))
        check("installer launch returns the process handle", result is sentinel)
        if sys.platform == "win32":
            check("installer launch is detached on Windows", bool(kwargs.get("creationflags")), str(kwargs))


def test_settings() -> None:
    check("update checking defaults to enabled", Settings().update_check_enabled is True)
    check("update setting is editable", "update_check_enabled" in EDITABLE_KEYS)
    with tempfile.TemporaryDirectory(prefix="egressscope-update-settings-") as temp:
        path = Path(temp) / "config.json"
        store = ConfigStore(path)
        store.update({"update_check_enabled": False})
        saved = json.loads(path.read_text(encoding="utf-8"))
        check("update setting persists to config.json", saved.get("update_check_enabled") is False, str(saved))
        check("in-memory setting reflects the update", store.settings.update_check_enabled is False)

        raw = json.loads(path.read_text(encoding="utf-8"))
        raw["update_check_enabled"] = True
        path.write_text(json.dumps(raw), encoding="utf-8")
        changed = store.reload_if_changed()
        check(
            "external edit of the update setting hot-reloads",
            "update_check_enabled" in changed and store.settings.update_check_enabled is True,
            str(changed),
        )


def test_check_update_cli() -> None:
    import app as app_module

    args = app_module.parse_args(["--check-update"])
    check("--check-update is parsed", args.check_update is True)
    fake = updater.empty_update_result("0.3.2")
    fake.update({"ok": True, "latest": "0.4.0", "available": True, "tag": "v0.4.0"})
    output = io.StringIO()
    with mock.patch.object(app_module.updater, "check_for_update", return_value=fake), \
         contextlib.redirect_stdout(output):
        code = app_module._run_check_update()
    try:
        payload = json.loads(output.getvalue())
    except ValueError:
        payload = {}
    check("--check-update exits successfully", code == 0, str(code))
    check("--check-update prints the JSON result", payload.get("latest") == "0.4.0", output.getvalue())


def run() -> None:
    print("\nEgressScope updater test")
    print("========================")
    test_semver()
    test_newer_release()
    test_no_update()
    test_prerelease_ignored()
    test_non_windows_not_installable()
    test_network_failure()
    test_download_and_checksum()
    test_release_assets_host()
    test_sha256_mismatch_deletes_file()
    test_download_host_allowlist()
    test_launch_installer()
    test_settings()
    test_check_update_cli()
    print("\n========================")
    print(f"{len(PASSED)} passed, {len(FAILED)} failed")
    if FAILED:
        for name in FAILED:
            print("  - " + name)
        raise SystemExit(1)


if __name__ == "__main__":
    run()
