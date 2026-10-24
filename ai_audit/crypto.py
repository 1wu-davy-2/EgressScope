from __future__ import annotations

import ctypes
import hashlib
import logging
import os
import secrets
import sys
from ctypes import wintypes
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

log = logging.getLogger(__name__)

_ENTROPY = b"EgressScope.master-key.v1"
_KEY_MAGIC = b"EGS1"


class CryptoError(RuntimeError):
    pass


class _DataBlob(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]


def _dpapi_call(func_name: str, data: bytes) -> bytes:
    crypt32 = ctypes.windll.crypt32
    kernel32 = ctypes.windll.kernel32
    buffer = ctypes.create_string_buffer(data, len(data))
    entropy = ctypes.create_string_buffer(_ENTROPY, len(_ENTROPY))
    blob_in = _DataBlob(len(data), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_char)))
    entropy_blob = _DataBlob(len(_ENTROPY), ctypes.cast(entropy, ctypes.POINTER(ctypes.c_char)))
    blob_out = _DataBlob()
    func = getattr(crypt32, func_name)
    func.argtypes = [
        ctypes.POINTER(_DataBlob),
        wintypes.LPCWSTR,
        ctypes.POINTER(_DataBlob),
        ctypes.c_void_p,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(_DataBlob),
    ]
    func.restype = wintypes.BOOL
    ok = func(
        ctypes.byref(blob_in),
        "EgressScope local audit key",
        ctypes.byref(entropy_blob),
        None,
        None,
        0x1,  # CRYPTPROTECT_UI_FORBIDDEN
        ctypes.byref(blob_out),
    )
    if not ok:
        raise CryptoError(f"{func_name} failed with error {ctypes.get_last_error()}")
    try:
        return ctypes.string_at(blob_out.pbData, blob_out.cbData)
    finally:
        kernel32.LocalFree(blob_out.pbData)


def _protect(data: bytes) -> bytes:
    if sys.platform == "win32":
        return b"DPAPI1" + _dpapi_call("CryptProtectData", data)
    log.warning("DPAPI unavailable on this platform; master key is stored with file permissions only")
    return b"PLAIN1" + data


def _unprotect(data: bytes) -> bytes:
    if data.startswith(b"DPAPI1"):
        if sys.platform != "win32":
            raise CryptoError("DPAPI-protected key cannot be opened on this platform")
        return _dpapi_call("CryptUnprotectData", data[6:])
    if data.startswith(b"PLAIN1"):
        return data[6:]
    raise CryptoError("Unknown key file format")


class SecureBox:
    """Authenticated encryption for captured request/response bodies."""

    def __init__(self, key_path: Path) -> None:
        self.key_path = key_path
        self._key = self._load_or_create()
        self._aes = AESGCM(self._key)

    def _load_or_create(self) -> bytes:
        if self.key_path.exists():
            protected = self.key_path.read_bytes()
            if not protected.startswith(_KEY_MAGIC):
                raise CryptoError("Unrecognized master key file")
            raw = _unprotect(protected[len(_KEY_MAGIC):])
            if len(raw) != 32:
                raise CryptoError("Corrupt master key")
            return raw

        key = secrets.token_bytes(32)
        self.key_path.parent.mkdir(parents=True, exist_ok=True)
        self.key_path.write_bytes(_KEY_MAGIC + _protect(key))
        try:
            os.chmod(self.key_path, 0o600)
        except OSError:
            pass
        return key

    def encrypt(self, plaintext: bytes, aad: bytes = b"") -> bytes:
        nonce = secrets.token_bytes(12)
        return nonce + self._aes.encrypt(nonce, plaintext, aad)

    def decrypt(self, payload: bytes | None, aad: bytes = b"") -> bytes | None:
        if not payload:
            return None
        if len(payload) < 13:
            raise CryptoError("Encrypted payload is too short")
        nonce, ciphertext = payload[:12], payload[12:]
        return self._aes.decrypt(nonce, ciphertext, aad)

    def available(self) -> bool:
        return self._key is not None


def sha256_hex(data: bytes | str | None) -> str:
    if data is None:
        return ""
    if isinstance(data, str):
        data = data.encode("utf-8", "replace")
    return hashlib.sha256(data).hexdigest()
