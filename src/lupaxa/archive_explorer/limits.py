"""Resource budgets for untrusted archives."""

from __future__ import annotations

import time
from dataclasses import dataclass

from lupaxa.archive_explorer.errors import AppError, ExitCode

GIBIBYTE = 1024**3


@dataclass
class Limits:
    """Configurable ceilings. Zero disables a byte or count ceiling."""

    max_depth: int = 5
    max_members: int = 100_000
    max_member_bytes: int = GIBIBYTE
    max_decompressed_bytes: int = 4 * GIBIBYTE
    max_temp_bytes: int = 2 * GIBIBYTE
    max_seconds: float | None = None
    max_line_length: int = 16_384
    workers: int = 1
    suspicious_ratio: int = 100
    max_path_components: int = 40
    max_diff_bytes: int = 2 * 1024 * 1024


class Budget:
    """Cumulative accounting shared across nested archives."""

    def __init__(self, limits: Limits) -> None:
        self.limits = limits
        self.started = time.monotonic()
        self.members = 0
        self.decompressed = 0
        self.temporary = 0

    def check_time(self) -> None:
        """Raise when the processing deadline has passed."""
        if self.limits.max_seconds is None:
            return
        if time.monotonic() - self.started > self.limits.max_seconds:
            raise AppError("processing time limit exceeded", ExitCode.LIMIT)

    def charge_member(self) -> None:
        """Count one visited member."""
        self.members += 1
        if self.limits.max_members and self.members > self.limits.max_members:
            raise AppError("member count limit exceeded", ExitCode.LIMIT)
        self.check_time()

    def check_declared(self, size: int | None) -> None:
        """Refuse a member whose declared size cannot fit the budget."""
        if size is None:
            return
        if self.limits.max_member_bytes and size > self.limits.max_member_bytes:
            raise AppError("single member size limit exceeded", ExitCode.LIMIT)
        if (
            self.limits.max_decompressed_bytes
            and self.decompressed + size > self.limits.max_decompressed_bytes
        ):
            raise AppError("decompressed byte budget exceeded", ExitCode.LIMIT)

    def account_read(self, chunk: int, member_total: int) -> None:
        """Charge bytes that were actually decompressed."""
        if chunk < 0:
            return
        if self.limits.max_member_bytes and member_total > self.limits.max_member_bytes:
            raise AppError("single member size limit exceeded", ExitCode.LIMIT)
        self.decompressed += chunk
        if (
            self.limits.max_decompressed_bytes
            and self.decompressed > self.limits.max_decompressed_bytes
        ):
            raise AppError("decompressed byte budget exceeded", ExitCode.LIMIT)
        self.check_time()

    def charge_temp(self, size: int) -> None:
        """Charge temporary disk usage."""
        self.temporary += size
        if self.limits.max_temp_bytes and self.temporary > self.limits.max_temp_bytes:
            raise AppError("temporary storage limit exceeded", ExitCode.LIMIT)

    def check_depth(self, depth: int) -> None:
        """Raise when nested archive depth exceeds the ceiling."""
        if self.limits.max_depth and depth > self.limits.max_depth:
            raise AppError("nested archive depth limit exceeded", ExitCode.LIMIT)
