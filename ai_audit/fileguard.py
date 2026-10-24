from __future__ import annotations

import logging
import os
import threading
import time
from pathlib import Path

import psutil

from .paths import AppPaths

log = logging.getLogger(__name__)

HIGH_NAMES = {
    ".env",
    ".npmrc",
    ".pypirc",
    ".netrc",
    "id_rsa",
    "id_ed25519",
    "id_ecdsa",
    "authorized_keys",
    "credentials",
    "secrets",
    "wallet.dat",
    "key4.db",
    "logins.json",
    "cookies.sqlite",
}
HIGH_EXTS = {".pem", ".key", ".pfx", ".p12", ".kdbx", ".ppk", ".ovpn", ".sqlite", ".db", ".wallet"}
MEDIUM_EXTS = {
    ".txt",
    ".md",
    ".json",
    ".yml",
    ".yaml",
    ".csv",
    ".tsv",
    ".xml",
    ".sql",
    ".doc",
    ".docx",
    ".xls",
    ".xlsx",
    ".ppt",
    ".pptx",
    ".pdf",
    ".rtf",
    ".zip",
    ".rar",
    ".7z",
    ".tar",
    ".gz",
    ".py",
    ".js",
    ".ts",
    ".tsx",
    ".jsx",
    ".java",
    ".go",
    ".rs",
    ".rb",
    ".php",
    ".cs",
    ".cpp",
    ".c",
    ".h",
    ".sh",
    ".ps1",
}
NOISE_EXTS = {".log", ".tmp", ".temp", ".cache", ".lock", ".pyc", ".swp", ".db-wal", ".db-shm"}
SYSTEM_PROCESSES = {
    "system",
    "system idle process",
    "registry",
    "memory compression",
    "svchost.exe",
    "csrss.exe",
    "wininit.exe",
    "services.exe",
    "lsass.exe",
    "smss.exe",
    "msmpeng.exe",
    "searchindexer.exe",
    "dwm.exe",
    "fontdrvhost.exe",
    "runtimebroker.exe",
    "sihost.exe",
    "ctfmon.exe",
}

CANARY_FILES: dict[str, str] = {
    "customer_export_2026.csv": (
        "customer_id,name,phone,email,contract_value\n"
        "CN-1042,林晨,13800000012,lin.chen@example.com,182000\n"
        "CN-1043,周雨,13800000023,zhou.yu@example.com,95000\n"
        "CN-1044,陈默,13800000034,chen.mo@example.com,241500\n"
    ),
    "aws_credentials_backup.txt": (
        "[default]\n"
        "aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n"
        "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
        "region = us-east-1\n"
    ),
    "id_rsa_backup.txt": (
        "-----BEGIN OPENSSH PRIVATE KEY-----\n"
        "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn\n"
        "NhAAAAAwEAAQAAAYEAvEgressScopeCanaryDecoyOnlyDoNotUseThisKeyMaterialAAA\n"
        "-----END OPENSSH PRIVATE KEY-----\n"
    ),
}


def canary_directory(paths: AppPaths, configured: str = "") -> Path:
    if configured:
        return Path(configured).expanduser()
    documents = Path.home() / "Documents"
    if documents.exists():
        return documents / "EgressScope Canaries"
    return paths.canaries


def create_canary_files(paths: AppPaths, store, configured: str = "") -> dict:
    target = canary_directory(paths, configured)
    target.mkdir(parents=True, exist_ok=True)
    created: list[str] = []
    for name, content in CANARY_FILES.items():
        path = target / name
        if not path.exists():
            path.write_text(content, encoding="utf-8")
        store.add_canary(name, str(path))
        created.append(str(path))
    return {"directory": str(target), "files": created}


def remove_canary_files(paths: AppPaths, store, configured: str = "") -> dict:
    target = canary_directory(paths, configured).resolve()
    removed: list[str] = []
    for row in store.list_canaries():
        path = Path(row["path"])
        try:
            resolved = path.resolve()
            if resolved.parent == target and resolved.name in CANARY_FILES:
                resolved.unlink(missing_ok=True)
                removed.append(str(resolved))
        except OSError:
            log.warning("failed to remove canary %s", path, exc_info=True)
    store.remove_canary_rows()
    try:
        target.rmdir()
    except OSError:
        pass
    return {"directory": str(target), "removed": removed}


class FileGuard:
    """Lightweight beta: correlate network-active processes with open sensitive files.

    This does not perform full file-read auditing. It samples open handles and only
    stores file metadata, never user file content.
    """

    def __init__(self, app) -> None:
        self.app = app
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._lock = threading.RLock()
        self._recent_pids: dict[int, tuple[float, str]] = {}
        self._seen: dict[tuple[int, str], float] = {}
        self.last_scan = 0.0
        self.last_error = ""
        self.scans = 0
        self.events = 0
        self._watch_roots = self._normalize_watch_roots()
        self._high_roots: list[str] = []

    def _normalize_watch_roots(self) -> list[str]:
        roots = []
        for raw in self.app.settings.watch_paths:
            try:
                roots.append(os.path.normcase(os.path.abspath(os.path.expandvars(raw))))
            except (OSError, ValueError):
                continue
        home = os.path.normcase(os.path.abspath(os.path.expanduser("~")))
        self._high_roots = [
            os.path.join(home, ".ssh"),
            os.path.join(home, ".aws"),
            os.path.join(home, ".gnupg"),
            os.path.join(home, "AppData", "Roaming", "gcloud"),
        ]
        return roots

    def refresh_watch_paths(self) -> None:
        self._watch_roots = self._normalize_watch_roots()

    def note_egress(self, pid: int, name: str = "") -> None:
        if not pid or pid == os.getpid():
            return
        with self._lock:
            self._recent_pids[pid] = (time.time(), name)
            if len(self._recent_pids) > 400:
                cutoff = time.time() - 900
                self._recent_pids = {k: v for k, v in self._recent_pids.items() if v[0] >= cutoff}

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="egressscope-fileguard", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5)
        self._thread = None

    def _run(self) -> None:
        while not self._stop.is_set():
            if self.app.settings.file_guard_enabled:
                try:
                    self.scan()
                except Exception as exc:
                    self.last_error = f"{type(exc).__name__}: {exc}"
                    log.debug("file guard scan failed", exc_info=True)
            interval = max(1.0, float(self.app.settings.file_guard_interval or 4.0))
            self._stop.wait(interval)

    def _candidate_pids(self) -> list[int]:
        pids: set[int] = set()
        now = time.time()
        with self._lock:
            for pid, (ts, _) in self._recent_pids.items():
                if now - ts < 900:
                    pids.add(pid)
        try:
            for conn in psutil.net_connections(kind="tcp"):
                if conn.pid and conn.status in (psutil.CONN_ESTABLISHED, psutil.CONN_SYN_SENT, psutil.CONN_CLOSE_WAIT):
                    pids.add(int(conn.pid))
        except (psutil.AccessDenied, OSError) as exc:
            self.last_error = f"TCP table: {exc}"
        pids.discard(os.getpid())
        return list(pids)[:120]

    def scan(self) -> None:
        now = time.time()
        canaries = {}
        try:
            canaries = {
                os.path.normcase(os.path.abspath(row["path"])): row for row in self.app.store.list_canaries()
            }
        except Exception:
            log.debug("canary list unavailable", exc_info=True)
        for pid in self._candidate_pids():
            if self._stop.is_set():
                return
            try:
                proc = psutil.Process(pid)
                with proc.oneshot():
                    name = proc.name()
                    if name.lower() in SYSTEM_PROCESSES:
                        continue
                    try:
                        exe = proc.exe()
                    except (psutil.AccessDenied, OSError):
                        exe = ""
                    files = proc.open_files()
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, OSError):
                continue
            for item in files:
                raw_path = item.path
                try:
                    path = os.path.normcase(os.path.abspath(raw_path))
                except (OSError, ValueError):
                    continue
                if path.startswith(os.path.normcase(os.path.abspath(self.app.paths.data))):
                    continue
                is_canary = path in canaries
                sensitivity, watched = self._classify(path)
                if not is_canary and not watched:
                    continue
                key = (pid, path)
                with self._lock:
                    if now - self._seen.get(key, 0) < 300:
                        continue
                    self._seen[key] = now
                if is_canary:
                    sensitivity = "critical"
                try:
                    result = self.app.store.add_file_event(
                        pid=pid,
                        proc_name=name,
                        proc_path=exe,
                        path=raw_path,
                        action="open",
                        sensitivity=sensitivity,
                        canary=is_canary,
                    )
                    if result is not None:
                        self.events += 1
                        if is_canary:
                            log.warning("canary file opened: %s by %s (%s)", raw_path, name, pid)
                except Exception:
                    log.debug("failed to store file event", exc_info=True)
        self.last_scan = time.time()
        self.scans += 1
        with self._lock:
            if len(self._seen) > 8000:
                cutoff = now - 600
                self._seen = {k: v for k, v in self._seen.items() if v >= cutoff}

    def _classify(self, path: str) -> tuple[str, bool]:
        filename = os.path.basename(path)
        stem, ext = os.path.splitext(filename.lower())
        if ext in NOISE_EXTS:
            return "low", False
        for root in self._high_roots:
            if path == root or path.startswith(root + os.sep):
                if filename.lower() in ("known_hosts",):
                    return "low", False
                return "high", True
        for root in self._watch_roots:
            if path == root or path.startswith(root + os.sep):
                if filename.lower() in HIGH_NAMES or stem in HIGH_NAMES or ext in HIGH_EXTS:
                    return "high", True
                if any(token in stem for token in ("secret", "credential", "password", "token", "private", "wallet")):
                    return "high", True
                if ext in MEDIUM_EXTS:
                    return "medium", True
                return "low", False
        return "low", False

    def status(self) -> dict:
        return {
            "enabled": bool(self.app.settings.file_guard_enabled),
            "interval": self.app.settings.file_guard_interval,
            "scans": self.scans,
            "events": self.events,
            "last_scan": self.last_scan,
            "last_error": self.last_error,
            "watch_paths": self.app.settings.watch_paths,
            "canary_enabled": bool(self.app.settings.canary_enabled),
            "canary_dir": str(canary_directory(self.app.paths, self.app.settings.canary_dir)),
            "beta": True,
        }
