"""Open archives, address members, and run archive-level operations."""

from __future__ import annotations

import hashlib
import os
import tempfile
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path

from lupaxa.archive_explorer.backends import ArchiveSession, CountingReader, open_format
from lupaxa.archive_explorer.detect import canonical_format, detect_bytes, detect_path
from lupaxa.archive_explorer.errors import AppError, ExitCode
from lupaxa.archive_explorer.limits import Budget, Limits
from lupaxa.archive_explorer.models import Member
from lupaxa.archive_explorer.paths import normalise_path
from lupaxa.archive_explorer.selector import Segment


@dataclass
class Workspace:
    """Temporary files created while reading nested or solid archives."""

    directory: Path
    budget: Budget
    paths: list[Path] = field(default_factory=list)

    def spill(self, reader: CountingReader) -> Path:
        """Copy a stream to an unpredictable temporary file."""
        with tempfile.NamedTemporaryFile(dir=self.directory, prefix="ax-", delete=False) as handle:
            path = Path(handle.name)
            self.paths.append(path)
            try:
                while True:
                    chunk = reader.read(1024 * 1024)
                    if not chunk:
                        break
                    handle.write(chunk)
                    self.budget.charge_temp(len(chunk))
            except Exception:
                path.unlink(missing_ok=True)
                raise
            finally:
                reader.close()
        os.chmod(path, 0o600)
        return path

    def close(self) -> None:
        """Delete temporary files."""
        for path in self.paths:
            path.unlink(missing_ok=True)
        self.paths.clear()


def open_archive(
    path: Path,
    *,
    display_path: str | None = None,
    password: str | None = None,
    archive_format: str | None = None,
    force: bool = False,
) -> ArchiveSession:
    """Open an archive after checking its signature."""
    if not path.is_file():
        raise AppError(f"archive not found: {path}", ExitCode.FAILURE)
    detected = detect_path(path)
    requested = canonical_format(archive_format) if archive_format else None
    if requested and detected and requested != detected and not force:
        raise AppError(
            f"signature indicates {detected}, not {requested}",
            ExitCode.USAGE,
        )
    chosen = requested or detected
    if chosen is None:
        raise AppError(
            "unrecognised archive format. Extensions are hints and are not used as proof.",
            ExitCode.UNSUPPORTED,
        )
    session = open_format(
        chosen,
        path,
        display_path=display_path or path.name,
        password=password,
    )
    if requested and detected is None:
        session.limitations.append(
            "The archive format was requested explicitly because the signature was not recognised."
        )
    if force and requested and detected and requested != detected:
        session.limitations.append(
            f"Opened as {requested} despite a {detected} signature because --force was set."
        )
    return session


def select_member(members: list[Member], segment: Segment) -> Member:
    """Resolve one segment to a single member."""
    if segment.index is not None:
        matches = [member for member in members if member.index == segment.index]
    else:
        needle = segment.path or ""
        matches = [
            member
            for member in members
            if member.path == needle
            or member.normalised_path == needle
            or normalise_path(member.path) == needle
        ]
        if segment.occurrence is not None:
            matches = [member for member in matches if member.occurrence == segment.occurrence]
        elif len(matches) > 1:
            choices = ", ".join(f"{item.member_id}@@{item.occurrence}" for item in matches)
            raise AppError(
                f"member path {needle} is ambiguous ({choices}). "
                "Select it with @@occurrence, an index, or --selector.",
                ExitCode.AMBIGUOUS,
            )
    if not matches:
        target = segment.path or f"#{segment.index}"
        raise AppError(f"member not found: {target}", ExitCode.NOT_FOUND)
    if len(matches) > 1:
        raise AppError("member selection is ambiguous", ExitCode.AMBIGUOUS)
    return matches[0]


def resolve_chain(
    root: Path,
    segments: list[Segment],
    *,
    password: str | None,
    archive_format: str | None,
    force: bool,
    budget: Budget,
    workspace: Workspace,
    sessions: list[ArchiveSession],
) -> tuple[ArchiveSession, Member]:
    """Open nested archives until the final segment is a member."""
    budget.check_depth(1)
    session = open_archive(
        root,
        password=password,
        archive_format=archive_format,
        force=force,
    )
    sessions.append(session)
    if not segments:
        raise AppError("a member selector is required", ExitCode.USAGE)
    depth = 1
    for position, segment in enumerate(segments):
        member = select_member(session.list_members(), segment)
        if position == len(segments) - 1:
            return session, member
        depth += 1
        budget.check_depth(depth)
        reader = session.open_member(member, budget)
        spilled = workspace.spill(reader)
        nested_display = f"{session.display_path}::{member.normalised_path}"
        session = open_archive(spilled, display_path=nested_display, password=password, force=force)
        session.materialised = True
        session.limitations.append(
            "The nested archive was written to temporary storage to open it."
        )
        sessions.append(session)
    raise AppError("member selector did not resolve", ExitCode.FAILURE)


def sniff_nested(session: ArchiveSession, members: list[Member], budget: Budget) -> None:
    """Mark file members whose prefix is itself an archive."""
    for member in members:
        if member.member_type != "file" or member.encrypted or member.nested_format:
            continue
        try:
            with session.open_member(member, budget, stop_at=560) as reader:
                head = reader.read(560)
        except AppError:
            continue
        member.nested_format = detect_bytes(head) or _compressed_tar_hint(head)


def _compressed_tar_hint(head: bytes) -> str | None:
    kind = detect_bytes(head)
    return kind


def iter_nested(
    session: ArchiveSession,
    *,
    budget: Budget,
    workspace: Workspace,
    password: str | None,
    force: bool,
    max_depth: int,
    sessions: list[ArchiveSession],
    errors: list[str] | None = None,
) -> Iterator[Member]:
    """Yield members, descending into nested archives up to ``max_depth``."""

    def walk(current: ArchiveSession, depth: int) -> Iterator[Member]:
        members = current.list_members()
        sniff_nested(current, members, budget)
        for member in members:
            budget.charge_member()
            member.nesting_level = depth - 1
            yield member
            if depth >= max_depth or not member.nested_format or member.member_type != "file":
                continue
            try:
                budget.check_depth(depth + 1)
                reader = current.open_member(member, budget)
                spilled = workspace.spill(reader)
                nested = open_archive(
                    spilled,
                    display_path=f"{current.display_path}::{member.normalised_path}",
                    password=password,
                    force=force,
                )
                nested.materialised = True
                nested.limitations.append(
                    "This nested archive was materialised in temporary storage."
                )
                sessions.append(nested)
            except AppError as exc:
                if errors is not None:
                    errors.append(f"{member.virtual_path()}: {exc.message}")
                continue
            yield from walk(nested, depth + 1)

    yield from walk(session, 1)


def hash_member(session: ArchiveSession, member: Member, budget: Budget) -> str | None:
    """Return the SHA-256 of a regular file, or None when it cannot be read."""
    if member.member_type != "file":
        return None
    digest = hashlib.sha256()
    with session.open_member(member, budget) as reader:
        while True:
            chunk = reader.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def inferred_directories(members: list[Member]) -> list[Member]:
    """Return virtual directory nodes that the archive did not store explicitly."""
    explicit = {
        (member.normalised_path.rstrip("/") or member.normalised_path)
        for member in members
        if member.member_type == "directory"
    }
    found: set[str] = set()
    virtual: list[Member] = []
    for member in members:
        parts = [part for part in member.normalised_path.split("/") if part not in {"", "."}]
        parts = parts[:-1]
        running: list[str] = []
        for part in parts:
            running.append(part)
            path = "/".join(running) + "/"
            if path in explicit or path in found:
                continue
            found.add(path)
            virtual.append(
                Member(
                    index=0,
                    path=path,
                    normalised_path=path,
                    member_id="inferred",
                    member_type="directory",
                    size=0,
                    inferred=True,
                    archive_path=member.archive_path,
                    nesting_level=member.nesting_level,
                )
            )
    return virtual


def directory_sizes(members: list[Member]) -> dict[str, int | None]:
    """Sum declared file sizes under each virtual directory."""
    totals: dict[str, int] = {}
    incomplete: set[str] = set()
    for member in members:
        if member.member_type != "file":
            continue
        parts = [part for part in member.normalised_path.split("/") if part]
        if len(parts) <= 1:
            continue
        running: list[str] = []
        for part in parts[:-1]:
            running.append(part)
            key = "/".join(running) + "/"
            if member.size is None:
                incomplete.add(key)
            else:
                totals[key] = totals.get(key, 0) + member.size
    result: dict[str, int | None] = {}
    for key, total in totals.items():
        result[key] = None if key in incomplete else total
    for key in incomplete:
        result.setdefault(key, None)
    return result


def archive_summary(session: ArchiveSession, members: list[Member]) -> dict[str, object]:
    """Return archive-level facts that do not invent missing sizes."""
    files = [member for member in members if member.member_type == "file"]
    sizes = [member.size for member in files]
    complete = all(size is not None for size in sizes)
    declared = sum(size or 0 for size in sizes)
    compressed = session.path.stat().st_size
    encrypted_values = {member.encrypted for member in members}
    if True in encrypted_values:
        encrypted: bool | None = True
    elif encrypted_values == {False}:
        encrypted = False
    else:
        encrypted = None
    ratio = None
    if complete and declared and compressed:
        ratio = 1 - (compressed / declared)
    return {
        "path": session.display_path,
        "format": session.format_id,
        "compression": session.compression,
        "compressed_size": compressed,
        "declared_uncompressed_size": declared if files else 0,
        "declared_uncompressed_size_complete": complete,
        "compression_saving": ratio,
        "encrypted": encrypted,
        "backend": session.backend_name,
        "backend_version": session.backend_version,
        "comment": session.comment,
        "file_count": len(files),
        "directory_count": sum(1 for member in members if member.member_type == "directory"),
        "symlink_count": sum(1 for member in members if member.member_type == "symlink"),
        "hardlink_count": sum(1 for member in members if member.member_type == "hardlink"),
        "other_count": sum(1 for member in members if member.member_type == "other"),
        "member_count": len(members),
        "limitations": list(session.limitations),
    }


def make_workspace(temp_directory: Path | None, budget: Budget) -> Workspace:
    """Create a workspace directory for this process."""
    root = temp_directory or Path(tempfile.gettempdir())
    root.mkdir(parents=True, exist_ok=True)
    directory = Path(tempfile.mkdtemp(prefix="archive-explorer-", dir=root))
    return Workspace(directory=directory, budget=budget)


def close_sessions(sessions: list[ArchiveSession]) -> None:
    """Close every session, ignoring secondary failures."""
    for session in sessions:
        try:
            session.close()
        except OSError:
            continue


def limits_from(limits: Limits) -> Budget:
    """Start a budget from limits."""
    return Budget(limits)
