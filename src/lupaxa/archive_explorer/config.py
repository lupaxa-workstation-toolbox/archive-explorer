"""Optional TOML configuration.

Precedence is command-line options, then ``--config``, then the user file,
then built-in defaults. The user file is ``$ARCHIVE_EXPLORER_CONFIG`` when
that variable is set, otherwise the platform config directory.
"""

from __future__ import annotations

import os
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path

from lupaxa.archive_explorer.errors import ConfigError
from lupaxa.archive_explorer.limits import Limits

_OUTPUTS = {"text", "json", "jsonl", "markdown", "html"}
_BACKENDS = {
    "zipfile",
    "tarfile",
    "py7zr",
    "rarfile",
    "gzip",
    "bz2",
    "lzma",
    "zstandard",
    "unrar",
    "unar",
    "bsdtar",
    "7z",
}


@dataclass
class Settings:
    """Resolved settings after precedence is applied."""

    output_format: str = "text"
    colour: bool = True
    preferred_backends: list[str] | None = None
    limits: Limits | None = None
    temp_directory: Path | None = None
    default_encoding: str = "utf-8"
    hash_algorithm: str = "sha256"
    follow_symlinks: bool = False
    allow_password_env: bool = False
    cache_directory: Path | None = None
    report_format: str = "text"
    encoding_errors: str = "replace"
    source: Path | None = None

    def resolved_limits(self) -> Limits:
        """Return the active limits."""
        return self.limits if self.limits is not None else Limits()


def user_config_path(environ: dict[str, str], home: Path) -> Path | None:
    """Return the user configuration path when one is defined."""
    override = environ.get("ARCHIVE_EXPLORER_CONFIG")
    if override:
        return Path(override).expanduser()
    if sys.platform == "win32":
        base = Path(environ.get("APPDATA", str(home / "AppData" / "Roaming")))
        return base / "archive-explorer" / "config.toml"
    xdg = environ.get("XDG_CONFIG_HOME")
    root = Path(xdg).expanduser() if xdg else home / ".config"
    return root / "archive-explorer" / "config.toml"


def load_settings(
    environ: dict[str, str] | None = None,
    home: Path | None = None,
    explicit: Path | None = None,
) -> Settings:
    """Load settings from the explicit file or the user file."""
    env = dict(os.environ if environ is None else environ)
    home_path = home if home is not None else Path.home()
    path = explicit if explicit is not None else user_config_path(env, home_path)
    settings = Settings()
    if path is None or not path.is_file():
        if explicit is not None:
            raise ConfigError(f"configuration file not found: {explicit}")
        settings.limits = Limits()
        return settings
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ConfigError(f"cannot read configuration: {exc}") from exc
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"invalid configuration TOML: {exc}") from exc
    if not isinstance(data, dict):
        raise ConfigError("configuration must be a TOML table")
    settings.source = path
    _apply(settings, data)
    if settings.limits is None:
        settings.limits = Limits()
    return settings


def _apply(settings: Settings, data: dict[str, object]) -> None:
    limits = Limits()
    known = {
        "output_format",
        "colour",
        "color",
        "preferred_backends",
        "max_depth",
        "max_members",
        "max_decompressed_bytes",
        "max_temp_bytes",
        "max_member_bytes",
        "max_seconds",
        "worker_count",
        "temp_directory",
        "default_encoding",
        "hash_algorithm",
        "follow_symlinks",
        "suspicious_ratio",
        "max_path_components",
        "max_line_length",
        "max_diff_bytes",
        "allow_password_env",
        "cache_directory",
        "report_format",
        "encoding_errors",
    }
    unknown = sorted(set(data) - known)
    if unknown:
        raise ConfigError("unknown configuration keys: " + ", ".join(unknown))
    if "output_format" in data:
        settings.output_format = _choice(data["output_format"], _OUTPUTS, "output_format")
    if "colour" in data:
        settings.colour = _bool(data["colour"], "colour")
    if "color" in data:
        settings.colour = _bool(data["color"], "color")
    if "preferred_backends" in data:
        settings.preferred_backends = _backends(data["preferred_backends"])
    if "max_depth" in data:
        limits.max_depth = _non_negative(data["max_depth"], "max_depth")
    if "max_members" in data:
        limits.max_members = _non_negative(data["max_members"], "max_members")
    if "max_decompressed_bytes" in data:
        limits.max_decompressed_bytes = _non_negative(
            data["max_decompressed_bytes"], "max_decompressed_bytes"
        )
    if "max_temp_bytes" in data:
        limits.max_temp_bytes = _non_negative(data["max_temp_bytes"], "max_temp_bytes")
    if "max_member_bytes" in data:
        limits.max_member_bytes = _non_negative(data["max_member_bytes"], "max_member_bytes")
    if "max_seconds" in data:
        limits.max_seconds = _optional_seconds(data["max_seconds"])
    if "worker_count" in data:
        limits.workers = _positive(data["worker_count"], "worker_count")
    if "suspicious_ratio" in data:
        limits.suspicious_ratio = _positive(data["suspicious_ratio"], "suspicious_ratio")
    if "max_path_components" in data:
        limits.max_path_components = _positive(data["max_path_components"], "max_path_components")
    if "max_line_length" in data:
        limits.max_line_length = _positive(data["max_line_length"], "max_line_length")
    if "max_diff_bytes" in data:
        limits.max_diff_bytes = _positive(data["max_diff_bytes"], "max_diff_bytes")
    if "temp_directory" in data:
        settings.temp_directory = _optional_path(data["temp_directory"], "temp_directory")
    if "cache_directory" in data:
        settings.cache_directory = _optional_path(data["cache_directory"], "cache_directory")
    if "default_encoding" in data:
        settings.default_encoding = _encoding(data["default_encoding"])
    if "hash_algorithm" in data:
        algorithm = _text(data["hash_algorithm"], "hash_algorithm").lower()
        if algorithm != "sha256":
            raise ConfigError("hash_algorithm must be sha256")
        settings.hash_algorithm = algorithm
    if "follow_symlinks" in data:
        settings.follow_symlinks = _bool(data["follow_symlinks"], "follow_symlinks")
    if "allow_password_env" in data:
        settings.allow_password_env = _bool(data["allow_password_env"], "allow_password_env")
    if "report_format" in data:
        settings.report_format = _choice(data["report_format"], _OUTPUTS, "report_format")
    if "encoding_errors" in data:
        settings.encoding_errors = _choice(
            data["encoding_errors"], {"strict", "replace", "ignore"}, "encoding_errors"
        )
    settings.limits = limits


def _text(value: object, key: str) -> str:
    if not isinstance(value, str) or not value:
        raise ConfigError(f"{key} must be a non-empty string")
    return value


def _bool(value: object, key: str) -> bool:
    if not isinstance(value, bool):
        raise ConfigError(f"{key} must be a boolean")
    return value


def _non_negative(value: object, key: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ConfigError(f"{key} must be an integer of 0 or greater")
    return value


def _positive(value: object, key: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ConfigError(f"{key} must be an integer of 1 or greater")
    return value


def _optional_seconds(value: object) -> float | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int | float) or value <= 0:
        raise ConfigError("max_seconds must be a positive number")
    return float(value)


def _choice(value: object, options: set[str], key: str) -> str:
    text = _text(value, key).lower()
    if text not in options:
        raise ConfigError(f"{key} must be one of: " + ", ".join(sorted(options)))
    return text


def _backends(value: object) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ConfigError("preferred_backends must be a list of strings")
    names = [item.lower() for item in value]
    unknown = [item for item in names if item not in _BACKENDS]
    if unknown:
        raise ConfigError("unknown preferred backends: " + ", ".join(unknown))
    return names


def _optional_path(value: object, key: str) -> Path | None:
    if value is None:
        return None
    return Path(_text(value, key)).expanduser()


def _encoding(value: object) -> str:
    name = _text(value, "default_encoding")
    try:
        "text".encode(name)
    except LookupError as exc:
        raise ConfigError(f"unknown default_encoding: {name}") from exc
    return name
