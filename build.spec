# -*- mode: python ; coding: utf-8 -*-
import os
import sys

from PyInstaller.utils.hooks import collect_all, copy_metadata

IS_WINDOWS = sys.platform == "win32"

datas = [("web", "web")]
binaries = []
hiddenimports = [
    "mitmproxy.tools.dump",
    "mitmproxy.tools.main",
    "mitmproxy.addons.proxyserver",
    "sqlite3",
    "tkinter",
    "tkinter.ttk",
    "tkinter.filedialog",
    "tkinter.messagebox",
]
if IS_WINDOWS:
    hiddenimports.append("winreg")
    openssl_dll = os.environ.get("EGRESS_SCOPE_OPENSSL_DLL")
    if openssl_dll:
        binaries.append((openssl_dll, "."))

for package in ("mitmproxy", "mitmproxy_rs"):
    package_datas, package_binaries, package_hidden = collect_all(package)
    datas += package_datas
    binaries += package_binaries
    hiddenimports += package_hidden

for dist in ("mitmproxy", "mitmproxy_rs", "psutil", "cryptography"):
    try:
        datas += copy_metadata(dist)
    except Exception:
        pass

a = Analysis(
    ["app.py"],
    pathex=[],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["playwright", "pytest"],
    noarchive=False,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="EgressScope",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=not IS_WINDOWS,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
