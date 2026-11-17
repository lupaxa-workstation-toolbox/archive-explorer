"""Shared data types for archives and members."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

SCHEMA_VERSION = "1.0"


@dataclass
class Member:
    """One archive member, real or inferred."""

    index: int
    path: str
    normalised_path: str = ""
    occurrence: int = 1
    member_id: str = ""
    member_type: str = "file"
    size: int | None = None
    compressed_size: int | None = None
    mtime: datetime | None = None
    mtime_timezone: str | None = None
    permissions: int | None = None
    compression: str | None = None
    encrypted: bool | None = None
    link_target: str | None = None
    checksum_algorithm: str | None = None
    checksum_value: str | None = None
    filename_encoding: str | None = None
    inferred: bool = False
    nesting_level: int = 0
    archive_path: str = ""
    nested_format: str | None = None

    def virtual_path(self) -> str:
        """Return the display path, including the archive chain."""
        base = self.normalised_path or self.path
        shown = base if self.occurrence == 1 else f"{base}@@{self.occurrence}"
        if not self.archive_path:
            return shown
        return f"{self.archive_path}::{shown}"

    def to_dict(self) -> dict[str, object]:
        """Return the stable JSON representation."""
        checksum: dict[str, str] | None = None
        if self.checksum_algorithm and self.checksum_value:
            checksum = {
                "algorithm": self.checksum_algorithm,
                "value": self.checksum_value,
            }
        return {
            "id": self.member_id,
            "path": self.path,
            "normalised_path": self.normalised_path,
            "virtual_path": self.virtual_path(),
            "occurrence": self.occurrence,
            "type": self.member_type,
            "size": self.size,
            "compressed_size": self.compressed_size,
            "mtime": self.mtime.isoformat() if self.mtime else None,
            "mtime_timezone": self.mtime_timezone,
            "permissions": self.permissions,
            "compression": self.compression,
            "encrypted": self.encrypted,
            "link_target": self.link_target,
            "checksum": checksum,
            "filename_encoding": self.filename_encoding,
            "inferred": self.inferred,
            "nesting_level": self.nesting_level,
            "archive": self.archive_path,
            "nested_format": self.nested_format,
        }


@dataclass
class Finding:
    """One safety finding."""

    finding_id: str
    member: str | None
    severity: str
    explanation: str
    consequence: str
    action: str
    limitations: str

    def to_dict(self) -> dict[str, object]:
        """Return the stable JSON representation."""
        return {
            "id": self.finding_id,
            "member": self.member,
            "severity": self.severity,
            "explanation": self.explanation,
            "consequence": self.consequence,
            "action": self.action,
            "limitations": self.limitations,
        }


@dataclass
class Capability:
    """Runtime capability of one archive format."""

    format_id: str
    detection: bool
    inspection: bool
    listing: bool
    streaming: bool
    extraction: bool
    integrity: bool
    encryption: bool
    nested: bool
    random_access: bool
    backend: str
    backend_version: str
    available: bool
    optional: bool
    limitations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        """Return the stable JSON representation."""
        return {
            "format": self.format_id,
            "detection": self.detection,
            "inspection": self.inspection,
            "listing": self.listing,
            "streaming": self.streaming,
            "extraction": self.extraction,
            "integrity": self.integrity,
            "encryption": self.encryption,
            "nested": self.nested,
            "random_access": self.random_access,
            "backend": self.backend,
            "backend_version": self.backend_version,
            "available": self.available,
            "optional": self.optional,
            "limitations": list(self.limitations),
        }
