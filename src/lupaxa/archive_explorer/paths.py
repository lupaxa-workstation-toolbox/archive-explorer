"""Path normalisation and extraction confinement."""

from __future__ import annotations

import os
import re
import unicodedata
from pathlib import Path

from lupaxa.archive_explorer.errors import AppError, ExitCode

_RESERVED = {"CON", "PRN", "AUX", "NUL"}
_RESERVED.update({f"COM{index}" for index in range(1, 10)})
_RESERVED.update({f"LPT{index}" for index in range(1, 10)})
_INVALID = re.compile(r"[\x00-\x1f<>:\"|?*]")
_DRIVE = re.compile(r"^[A-Za-z]:")


def normalise_path(path: str) -> str:
    """Return a display path without merging distinct members.

    Slashes are unified and a leading ``./`` is removed. Absolute markers,
    parent segments, and duplicate spellings are preserved.
    """
    text = path.replace("\\", "/")
    while text.startswith("./"):
        text = text[2:]
    return text


def path_parts(path: str) -> list[str]:
    """Split a member path into non-empty components."""
    return [part for part in normalise_path(path).split("/") if part not in {"", "."}]


def is_absolute_member(path: str) -> bool:
    """Return whether a member path is absolute on any supported platform."""
    text = path.replace("\\", "/")
    if text.startswith("/"):
        return True
    if text.startswith("//"):
        return True
    return _DRIVE.match(text) is not None


def is_unc(path: str) -> bool:
    """Return whether a member path is a UNC path."""
    text = path.replace("\\", "/")
    return text.startswith("//")


def has_traversal(path: str) -> bool:
    """Return whether any component is a parent reference."""
    return ".." in path_parts(path)


def is_windows_drive(path: str) -> bool:
    """Return whether a member path starts with a Windows drive."""
    return _DRIVE.match(path.replace("\\", "/")) is not None


def is_reserved_name(part: str) -> bool:
    """Return whether a path component is reserved on Windows."""
    stem = part.split(".", 1)[0].rstrip(" .").upper()
    return stem in _RESERVED


def has_invalid_characters(path: str) -> bool:
    """Return whether a path contains characters that are unsafe on Windows."""
    for part in path_parts(path):
        if _INVALID.search(part) or part.endswith(" ") or part.endswith("."):
            return True
    return False


def confine(root: Path, relative: str) -> Path:
    """Join ``relative`` under ``root`` or refuse the member path."""
    if is_absolute_member(relative) or is_unc(relative) or is_windows_drive(relative):
        raise AppError(f"refusing absolute member path: {relative}", ExitCode.SAFETY)
    parts = path_parts(relative)
    if not parts:
        raise AppError("refusing empty member path", ExitCode.SAFETY)
    if any(part == ".." for part in parts):
        raise AppError(f"refusing parent traversal: {relative}", ExitCode.SAFETY)
    for part in parts:
        if is_reserved_name(part) or _INVALID.search(part):
            raise AppError(f"refusing unsafe path component: {part}", ExitCode.SAFETY)
        if part.endswith(" ") or part.endswith("."):
            raise AppError(f"refusing unsafe path component: {part}", ExitCode.SAFETY)
    current = root
    for part in parts:
        if current.is_symlink():
            raise AppError("refusing to traverse a symlink in the destination", ExitCode.SAFETY)
        current = current / part
    try:
        current.relative_to(root)
    except ValueError as exc:
        raise AppError("member path escapes the destination", ExitCode.SAFETY) from exc
    return current


def same_nfc(left: str, right: str) -> bool:
    """Return whether two paths collide under Unicode NFC."""
    return (
        unicodedata.normalize("NFC", left) == unicodedata.normalize("NFC", right) and left != right
    )


def open_no_follow(path: Path) -> int:
    """Open a file for writing without following a final symlink."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if nofollow:
        flags |= nofollow
    return os.open(path, flags, 0o600)
