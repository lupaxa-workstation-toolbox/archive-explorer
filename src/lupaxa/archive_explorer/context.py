"""Invocation state shared by every command."""

from __future__ import annotations

import os
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import BinaryIO, TextIO

from lupaxa.archive_explorer.archive import Workspace
from lupaxa.archive_explorer.backends import ArchiveSession
from lupaxa.archive_explorer.config import Settings
from lupaxa.archive_explorer.errors import AppError, ExitCode, redact
from lupaxa.archive_explorer.limits import Budget
from lupaxa.archive_explorer.render import dumps, dumps_lines, report_html, report_markdown


@dataclass
class Context:
    """Runtime state for one invocation."""

    stdout: BinaryIO
    stderr: TextIO
    settings: Settings
    budget: Budget
    workspace: Workspace
    sessions: list[ArchiveSession] = field(default_factory=list)
    password: str | None = None
    colour: bool = False
    verbose: bool = False
    quiet: bool = False
    force: bool = False
    archive_format: str | None = None
    output_format: str = "text"
    output_path: Path | None = None
    follow_symlinks: bool = False
    secrets: list[str] = field(default_factory=list)

    def emit(
        self,
        payload: dict[str, object],
        text: str,
        records: list[dict[str, object]] | None = None,
    ) -> None:
        """Write a command result to stdout or ``--output``."""
        if self.output_format == "json":
            data = dumps(payload).encode("utf-8")
        elif self.output_format == "jsonl":
            data = dumps_lines(payload, records or []).encode("utf-8")
        elif self.output_format == "markdown":
            data = report_markdown(payload).encode("utf-8")
        elif self.output_format == "html":
            data = report_html(payload).encode("utf-8")
        else:
            data = text.encode("utf-8")
        if self.output_path is not None:
            write_atomic(self.output_path, data)
            return
        self.stdout.write(data)
        self.stdout.flush()

    def warn(self, message: str) -> None:
        """Write a diagnostic when quiet mode is off."""
        if self.quiet or self.output_format != "text":
            return
        self.stderr.write(redact(message, self.secrets) + "\n")


def write_atomic(path: Path, data: bytes) -> None:
    """Replace ``path`` only after the temporary file is complete."""
    if path.is_symlink():
        raise AppError("refusing to write through a symlink", ExitCode.SAFETY)
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(dir=path.parent, prefix=".archive-explorer-")
    temporary_path = Path(temporary)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
        os.replace(temporary_path, path)
    except Exception:
        temporary_path.unlink(missing_ok=True)
        raise
