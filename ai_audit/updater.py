"""GitHub Releases update checking and verified installer download.

Only the public GitHub Releases API is contacted. No audit data, hostnames or
local identifiers are sent. Downloads must use HTTPS and a GitHub-controlled
hostname, and a SHA-256 checksum is mandatory before an installer is launched.
"""
from __future__ import annotations

import hashlib
import json
import platform as _platform
import re
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

RELEASES_LATEST_URL = "https://api.github.com/repos/1wu-davy-2/EgressScope/releases/latest"
PROJECT_URL = "https://github.com/1wu-davy-2/EgressScope"
ALLOWED_DOWNLOAD_HOSTS = frozenset({
    "github.com",
    "api.github.com",
    "objects.githubusercontent.com",
    "release-assets.githubusercontent.com",
})
MAX_DOWNLOAD_BYTES = 200 * 1024 * 1024
MAX_CHECKSUM_BYTES = 1024 * 1024
CHECKSUM_FALLBACK_NAMES = ("SHA256SUMS.txt", "sha256sums.txt")
SETUP_NAME_PREFIX = "EgressScope-Setup-"
_VERSION_RE = re.compile(r"^[vV]?(\d+)\.(\d+)\.(\d+)$")
_SHA_LINE_RE = re.compile(r"^([0-9a-fA-F]{64})(?:\s+[* ]?(.+?))?\s*$")


def parse_version(value: Any) -> tuple[int, int, int] | None:
    """Parse a numeric X.Y.Z version, tolerating a leading v."""
    match = _VERSION_RE.match(str(value or "").strip())
    if not match:
        return None
    return int(match.group(1)), int(match.group(2)), int(match.group(3))


def compare_versions(left: Any, right: Any) -> int:
    """Return -1, 0 or 1 using numeric semver ordering (0.10.0 > 0.9.9)."""
    a = parse_version(left)
    b = parse_version(right)
    if a is None or b is None:
        raise ValueError(f"invalid numeric version: {left!r} / {right!r}")
    return (a > b) - (a < b)


def _version_text(version: tuple[int, int, int]) -> str:
    return ".".join(str(part) for part in version)


def _platform_label() -> str:
    machine = (_platform.machine() or "unknown").strip().lower() or "unknown"
    return f"{sys.platform}-{machine}"


def _is_windows_x64() -> bool:
    if sys.platform != "win32":
        return False
    return (_platform.machine() or "").strip().lower() in {"amd64", "x86_64", "x64"}


def empty_update_result(current_version: str, error: str = "") -> dict[str, Any]:
    """Return a fully populated update payload for UI and API consumers."""
    return {
        "ok": False,
        "current": str(current_version or ""),
        "latest": "",
        "available": False,
        "tag": "",
        "published_at": "",
        "notes_url": "",
        "asset_name": "",
        "asset_url": "",
        "sha256_url": "",
        "installable": False,
        "platform": _platform_label(),
        "error": str(error or ""),
    }


def _user_agent(current_version: str) -> str:
    return f"EgressScope/{current_version or 'unknown'} (+{PROJECT_URL})"


def _require_allowed_url(url: str) -> None:
    try:
        parts = urlsplit(str(url or ""))
        host = (parts.hostname or "").lower()
    except ValueError as exc:
        raise ValueError(f"无效的下载地址：{url!r}") from exc
    if parts.scheme != "https":
        raise ValueError(f"更新下载必须使用 HTTPS：{url!r}")
    if host not in ALLOWED_DOWNLOAD_HOSTS:
        raise ValueError(f"更新下载地址不在允许的 GitHub 域名内：{host or '(empty)'}")
    if parts.username or parts.password:
        raise ValueError("更新下载地址不能包含用户名或密码")


class _AllowedRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        _require_allowed_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


# Update checks must not depend on EgressScope's own MITM proxy being healthy.
_OPENER = urllib.request.build_opener(
    urllib.request.ProxyHandler({}),
    _AllowedRedirectHandler(),
)


def _open_url(url: str, *, timeout: float, headers: dict[str, str] | None = None):
    """Open an allowed HTTPS URL, validating redirect targets as they occur."""
    _require_allowed_url(url)
    request = urllib.request.Request(url, headers=headers or {})
    response = _OPENER.open(request, timeout=timeout)
    try:
        _require_allowed_url(response.geturl())
    except Exception:
        response.close()
        raise
    return response


def _read_all(response, limit: int) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = response.read(65536)
        if not chunk:
            break
        total += len(chunk)
        if total > limit:
            raise ValueError(f"响应体超过允许的大小（{limit} 字节）")
        chunks.append(chunk)
    return b"".join(chunks)


def _fetch_json(url: str, *, timeout: float, headers: dict[str, str]) -> Any:
    response = _open_url(url, timeout=timeout, headers=headers)
    try:
        raw = _read_all(response, MAX_CHECKSUM_BYTES)
    finally:
        response.close()
    return json.loads(raw.decode("utf-8"))


def _fetch_checksum_text(url: str, *, timeout: float) -> str:
    response = _open_url(url, timeout=timeout)
    try:
        raw = _read_all(response, MAX_CHECKSUM_BYTES)
    finally:
        response.close()
    return raw.decode("utf-8", errors="replace")


def _asset_map(assets: Any) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    if not isinstance(assets, list):
        return result
    for asset in assets:
        if not isinstance(asset, dict):
            continue
        name = str(asset.get("name") or "")
        if name:
            result[name] = asset
    return result


def _lookup_asset(by_name: dict[str, dict[str, Any]], candidates: tuple[str, ...]) -> tuple[str, dict[str, Any]] | None:
    for name in candidates:
        if name in by_name:
            return name, by_name[name]
    lowered = {name.lower(): (name, asset) for name, asset in by_name.items()}
    for name in candidates:
        found = lowered.get(name.lower())
        if found:
            return found
    return None


def _select_assets(payload: dict[str, Any], latest: tuple[int, int, int], tag: str) -> tuple[str, dict[str, Any]] | None:
    by_name = _asset_map(payload.get("assets"))
    latest_text = _version_text(latest)
    candidates = [f"{SETUP_NAME_PREFIX}v{latest_text}.exe"]
    exact_tag_name = f"{SETUP_NAME_PREFIX}{tag}.exe"
    if exact_tag_name not in candidates:
        candidates.append(exact_tag_name)
    return _lookup_asset(by_name, tuple(candidates))


def _select_checksum(by_name: dict[str, dict[str, Any]], setup_name: str) -> tuple[str, dict[str, Any]] | None:
    candidates = [setup_name + ".sha256", *CHECKSUM_FALLBACK_NAMES]
    return _lookup_asset(by_name, tuple(candidates))


def _error_text(exc: BaseException) -> str:
    if isinstance(exc, urllib.error.HTTPError):
        return f"GitHub API 返回 HTTP {exc.code}"
    if isinstance(exc, urllib.error.URLError):
        return f"无法连接 GitHub：{exc.reason}"
    if isinstance(exc, (TimeoutError, OSError)):
        return f"网络请求失败：{exc}"
    if isinstance(exc, (ValueError, json.JSONDecodeError)):
        return f"更新信息解析失败：{exc}"
    return f"{type(exc).__name__}: {exc}"


def check_for_update(current_version: str, *, timeout: float = 8.0) -> dict[str, Any]:
    """Query the latest stable GitHub release and report whether an update exists."""
    current_text = str(current_version or "").strip()
    result = empty_update_result(current_text)
    current = parse_version(current_text)
    if current is None:
        result["error"] = f"当前版本不是数字 semver：{current_text or '(empty)'}"
        return result

    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": _user_agent(current_text),
        "X-GitHub-Api-Version": "2022-11-28",
    }
    try:
        payload = _fetch_json(RELEASES_LATEST_URL, timeout=timeout, headers=headers)
    except Exception as exc:
        result["error"] = _error_text(exc)
        return result

    if not isinstance(payload, dict):
        result["error"] = "GitHub 返回的 Release 不是 JSON 对象"
        return result
    if payload.get("draft") or payload.get("prerelease"):
        # /releases/latest normally excludes these; ignore defensively.
        result["ok"] = True
        return result

    tag = str(payload.get("tag_name") or "").strip()
    latest = parse_version(tag)
    if latest is None:
        result["error"] = f"无法解析 Release 标签：{tag or '(empty)'}"
        return result

    result["tag"] = tag
    result["latest"] = _version_text(latest)
    result["published_at"] = str(payload.get("published_at") or "")
    result["notes_url"] = str(payload.get("html_url") or "")
    result["available"] = compare_versions(_version_text(latest), _version_text(current)) > 0

    by_name = _asset_map(payload.get("assets"))
    setup = _select_assets(payload, latest, tag)
    if setup is not None:
        setup_name, setup_asset = setup
        result["asset_name"] = setup_name
        result["asset_url"] = str(setup_asset.get("browser_download_url") or "")
        checksum = _select_checksum(by_name, setup_name)
        if checksum is not None:
            result["sha256_url"] = str(checksum[1].get("browser_download_url") or "")

    installable = bool(
        result["available"]
        and _is_windows_x64()
        and result["asset_url"]
        and result["sha256_url"]
    )
    if installable:
        try:
            _require_allowed_url(result["asset_url"])
            _require_allowed_url(result["sha256_url"])
        except ValueError:
            installable = False
    result["installable"] = installable
    result["ok"] = True
    return result


def _safe_asset_name(info: dict[str, Any]) -> str:
    raw = str(info.get("asset_name") or "").strip()
    if not raw:
        raw = Path(urlsplit(str(info.get("asset_url") or "")).path).name
    name = Path(raw).name
    lowered = name.lower()
    if not lowered.startswith(SETUP_NAME_PREFIX.lower()) or not lowered.endswith(".exe"):
        raise ValueError(f"更新包文件名不合法：{name or '(empty)'}")
    return name


def _parse_sha256(text: str, asset_name: str) -> str:
    entries: list[tuple[str, str]] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        match = _SHA_LINE_RE.match(stripped)
        if not match:
            continue
        digest = match.group(1).lower()
        name = (match.group(2) or "").strip().strip("*").strip()
        entries.append((digest, name))
    if not entries:
        raise ValueError("校验文件中没有找到有效的 SHA-256 值")
    named = [entry for entry in entries if entry[1]]
    if named:
        for digest, name in named:
            if Path(name).name.lower() == asset_name.lower():
                return digest
        raise ValueError(f"校验文件中没有 {asset_name} 的 SHA-256 记录")
    if len(entries) == 1:
        return entries[0][0]
    raise ValueError(f"校验文件包含多个 SHA-256 值，但无法匹配 {asset_name}")


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _download_file(url: str, target: Path, *, timeout: float) -> None:
    response = _open_url(url, timeout=timeout)
    try:
        content_length = 0
        try:
            content_length = int(response.headers.get("Content-Length") or 0)
        except (TypeError, ValueError):
            content_length = 0
        if content_length > MAX_DOWNLOAD_BYTES:
            raise ValueError(f"更新包超过允许的大小（上限 {MAX_DOWNLOAD_BYTES} 字节）")
        written = 0
        with target.open("wb") as handle:
            while True:
                chunk = response.read(1024 * 1024)
                if not chunk:
                    break
                written += len(chunk)
                if written > MAX_DOWNLOAD_BYTES:
                    raise ValueError(f"更新包超过允许的大小（上限 {MAX_DOWNLOAD_BYTES} 字节）")
                handle.write(chunk)
    finally:
        response.close()


def download_update(info: dict[str, Any], dest_dir: Path | str | None = None, timeout: float = 30.0) -> Path:
    """Download and verify the setup exe. The file is deleted on any failure."""
    if not isinstance(info, dict):
        raise ValueError("更新信息无效")
    asset_url = str(info.get("asset_url") or "")
    sha_url = str(info.get("sha256_url") or "")
    if not asset_url or not sha_url:
        raise ValueError("更新信息缺少安装包或 SHA-256 校验地址")
    _require_allowed_url(asset_url)
    _require_allowed_url(sha_url)
    asset_name = _safe_asset_name(info)

    try:
        checksum_text = _fetch_checksum_text(sha_url, timeout=timeout)
        expected = _parse_sha256(checksum_text, asset_name)
    except ValueError:
        raise
    except Exception as exc:
        raise ValueError(f"获取 SHA-256 校验失败：{_error_text(exc)}") from exc

    target_dir = Path(dest_dir) if dest_dir else Path(tempfile.mkdtemp(prefix="egressscope-update-"))
    target_dir.mkdir(parents=True, exist_ok=True)
    target = target_dir / asset_name
    try:
        try:
            _download_file(asset_url, target, timeout=timeout)
        except ValueError:
            raise
        except Exception as exc:
            raise ValueError(f"下载更新包失败：{_error_text(exc)}") from exc
        actual = _sha256_file(target)
        if actual.lower() != expected.lower():
            raise ValueError(
                "SHA-256 校验失败：下载的更新包可能被篡改，文件已删除 "
                f"(expected {expected[:12]}…, got {actual[:12]}…)"
            )
    except Exception:
        target.unlink(missing_ok=True)
        raise
    return target


def launch_installer(path: Path | str) -> subprocess.Popen:
    """Start a verified Inno Setup installer in silent, no-restart mode."""
    installer = Path(path)
    if not installer.is_file():
        raise ValueError(f"安装包不存在：{installer}")
    if installer.suffix.lower() != ".exe":
        raise ValueError(f"不是 Windows 安装包：{installer.name}")
    args = [str(installer), "/SILENT", "/NORESTART", "/CLOSEAPPLICATIONS"]
    kwargs: dict[str, Any] = {
        "shell": False,
        "close_fds": True,
        "stdin": subprocess.DEVNULL,
        "stdout": subprocess.DEVNULL,
        "stderr": subprocess.DEVNULL,
    }
    if sys.platform == "win32":
        kwargs["creationflags"] = 0x00000008 | 0x00000200  # DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP
    return subprocess.Popen(args, **kwargs)
