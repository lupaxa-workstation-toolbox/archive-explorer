"""Identify archive formats from signatures, not file extensions."""

from __future__ import annotations

import bz2
import gzip
import lzma
from pathlib import Path

_ALIASES = {
    "zip": "zip",
    "jar": "zip",
    "tar": "tar",
    "tar.gz": "tar.gz",
    "tgz": "tar.gz",
    "tar.bz2": "tar.bz2",
    "tbz2": "tar.bz2",
    "tbz": "tar.bz2",
    "tar.xz": "tar.xz",
    "txz": "tar.xz",
    "tar.zst": "tar.zst",
    "tar.zstd": "tar.zst",
    "tzst": "tar.zst",
    "7z": "7z",
    "7zip": "7z",
    "rar": "rar",
    "gzip": "gzip",
    "gz": "gzip",
    "bzip2": "bzip2",
    "bz2": "bzip2",
    "xz": "xz",
    "zstd": "zstd",
    "zst": "zstd",
}


def canonical_format(name: str) -> str:
    """Return the canonical format id for a user-supplied alias."""
    key = name.strip().lower()
    if key not in _ALIASES:
        known = ", ".join(sorted(set(_ALIASES.values())))
        raise ValueError(f"unknown archive format {name!r}; expected one of: {known}")
    return _ALIASES[key]


def _tar_checksum_ok(header: bytes) -> bool:
    if len(header) < 512:
        return False
    stored = header[148:156]
    try:
        expected = int(stored.decode("ascii", errors="ignore").strip() or "0", 8)
    except ValueError:
        return False
    actual = sum(header[:148]) + sum(b" " * 8) + sum(header[156:512])
    return actual == expected


def looks_like_tar(blob: bytes) -> bool:
    """Return whether a byte string starts with a tar header."""
    if len(blob) < 512:
        return False
    if blob[257:262] == b"ustar":
        return True
    return _tar_checksum_ok(blob[:512]) and blob[0:1] != b"\x00"


def detect_bytes(blob: bytes) -> str | None:
    """Identify a format from a prefix, when the prefix is decisive."""
    if (
        blob.startswith(b"PK\x03\x04")
        or blob.startswith(b"PK\x05\x06")
        or blob.startswith(b"PK\x07\x08")
    ):
        return "zip"
    if blob.startswith(b"7z\xbc\xaf\x27\x1c"):
        return "7z"
    if blob.startswith(b"Rar!\x1a\x07"):
        return "rar"
    if looks_like_tar(blob):
        return "tar"
    if blob.startswith(b"\x1f\x8b"):
        return "gzip"
    if blob.startswith(b"BZh"):
        return "bzip2"
    if blob.startswith(b"\xfd7zXZ\x00"):
        return "xz"
    if blob.startswith(b"\x28\xb5\x2f\xfd"):
        return "zstd"
    return None


def _prefix(path: Path, opener: object, limit: int = 600) -> bytes | None:
    try:
        handle = opener(path, "rb")  # type: ignore[operator]
        with handle:
            return bytes(handle.read(limit))
    except (OSError, EOFError, gzip.BadGzipFile, lzma.LZMAError, ValueError):
        return None


def detect_path(path: Path) -> str | None:
    """Identify ``path`` from its signature and, for compressed streams, a short peek."""
    with path.open("rb") as handle:
        head = handle.read(560)
    kind = detect_bytes(head)
    if kind == "gzip":
        payload = _prefix(path, gzip.open)
        if payload is not None and looks_like_tar(payload):
            return "tar.gz"
        return "gzip"
    if kind == "bzip2":
        payload = _prefix(path, bz2.open)
        if payload is not None and looks_like_tar(payload):
            return "tar.bz2"
        return "bzip2"
    if kind == "xz":
        payload = _prefix(path, lzma.open)
        if payload is not None and looks_like_tar(payload):
            return "tar.xz"
        return "xz"
    if kind == "zstd":
        payload = _zstd_prefix(path)
        if payload is not None and looks_like_tar(payload):
            return "tar.zst"
        return "zstd"
    if kind == "tar":
        return "tar"
    return kind


def _zstd_prefix(path: Path) -> bytes | None:
    try:
        import zstandard
    except ImportError:
        return None
    try:
        with path.open("rb") as handle:
            reader = zstandard.ZstdDecompressor().stream_reader(handle)
            try:
                return bytes(reader.read(600))
            finally:
                reader.close()
    except (OSError, zstandard.ZstdError):
        return None


def compression_label(format_id: str) -> str | None:
    """Return the container compression for a format, when there is only one."""
    return {
        "tar.gz": "gzip",
        "tar.bz2": "bzip2",
        "tar.xz": "xz",
        "tar.zst": "zstd",
        "gzip": "gzip",
        "bzip2": "bzip2",
        "xz": "xz",
        "zstd": "zstd",
    }.get(format_id)


def is_compressed_tar(format_id: str) -> bool:
    """Return whether the format is a compressed tar stream."""
    return format_id in {"tar.gz", "tar.bz2", "tar.xz", "tar.zst"}
