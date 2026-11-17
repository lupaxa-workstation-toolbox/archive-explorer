"""Archive Explorer commands."""

from __future__ import annotations

import difflib
import fnmatch
import os
import re
import sys
import tempfile
from collections import defaultdict
from collections.abc import Callable, Iterable, Sequence
from datetime import datetime
from pathlib import Path

from lupaxa.archive_explorer.archive import (
    archive_summary,
    close_sessions,
    directory_sizes,
    hash_member,
    inferred_directories,
    iter_nested,
    open_archive,
    resolve_chain,
    select_member,
    sniff_nested,
)
from lupaxa.archive_explorer.backends import ArchiveSession, capabilities
from lupaxa.archive_explorer.context import Context, write_atomic
from lupaxa.archive_explorer.errors import AppError, ExitCode
from lupaxa.archive_explorer.models import Member
from lupaxa.archive_explorer.paths import confine, has_traversal, is_absolute_member
from lupaxa.archive_explorer.render import (
    diff_text,
    duplicates_text,
    envelope,
    escape_terminal,
    findings_text,
    formats_text,
    inspect_text,
    member_lines,
    test_text,
    tree_text,
)
from lupaxa.archive_explorer.safety import analyse
from lupaxa.archive_explorer.selector import Segment, parse_selector_json, parse_virtual_path


def run_inspect(
    ctx: Context, path: Path, *, detailed: bool, member: str | None, nested: bool
) -> int:
    """Inspect an archive and return an exit code."""
    session, members = _subject(ctx, path, member)
    sniff_nested(session, members, ctx.budget)
    summary = archive_summary(session, members)
    nested_count = sum(1 for item in members if item.nested_format)
    errors: list[str] = []
    if nested:
        for item in _descendants(ctx, session, errors):
            if item.nested_format and item.nesting_level:
                nested_count += 1
    findings = analyse(
        members,
        compressed_size=_as_int(summary.get("compressed_size")),
        limits=ctx.budget.limits,
    )
    times = [item.mtime for item in members if item.mtime is not None]
    files = [item for item in members if item.member_type == "file" and item.size is not None]
    largest = sorted(files, key=lambda item: item.size or 0, reverse=True)[: 10 if detailed else 5]
    dirs = sorted(
        ((name, size) for name, size in directory_sizes(members).items() if size is not None),
        key=lambda item: item[1],
        reverse=True,
    )[: 10 if detailed else 5]
    types: dict[str, int] = defaultdict(int)
    empty = 0
    methods: set[str] = set()
    encodings: set[str] = set()
    for item in members:
        if item.member_type == "file":
            types[Path(item.normalised_path).suffix.lower() or "(none)"] += 1
            if item.size == 0:
                empty += 1
        if item.compression:
            methods.add(item.compression)
        if item.filename_encoding:
            encodings.add(item.filename_encoding)
    limitations = list(summary["limitations"]) if isinstance(summary["limitations"], list) else []
    limitations.extend(errors)
    payload = envelope(
        "inspect",
        "partial" if errors else "completed",
        archive=summary,
        nested_archive_count=nested_count,
        earliest_mtime=min(times).isoformat() if times else None,
        latest_mtime=max(times).isoformat() if times else None,
        largest_members=[item.to_dict() for item in largest],
        largest_directories=[{"path": name, "size": size} for name, size in dirs],
        file_types=dict(types),
        empty_files=empty,
        warnings=[item.to_dict() for item in findings],
        limitations=limitations,
        detailed={
            "compression_methods": sorted(methods),
            "comment": session.comment,
            "duplicate_paths": sum(1 for item in members if item.occurrence > 1),
            "filename_encodings": sorted(encodings) or ["unspecified"],
        }
        if detailed
        else None,
    )
    ctx.emit(payload, inspect_text(payload, colour=ctx.colour))
    return ExitCode.PARTIAL if errors else ExitCode.OK


def run_list(ctx: Context, path: Path, args: object) -> int:
    """List archive members."""
    session = _root(ctx, path)
    members = _under(session.list_members(), _opt(args, "path"))
    entry_type = _opt(args, "entry_type")
    if entry_type:
        members = [item for item in members if item.member_type == entry_type]
    members = _sort(members, _opt(args, "sort"), bool(_opt(args, "descending")))
    offset = _required_int(_opt(args, "offset"))
    limit = _as_int(_opt(args, "limit"))
    members = members[offset : offset + limit if limit else None]
    records = [item.to_dict() for item in members]
    payload = envelope("list", "completed", archive={"path": session.display_path}, members=records)
    ctx.emit(payload, member_lines(records, long=bool(_opt(args, "long_format"))), records)
    return ExitCode.OK


def _tree(
    name: str,
    members: list[Member],
    *,
    depth: object,
    directories_only: bool,
    sizes: bool,
    prefix: object,
) -> dict[str, object]:
    """Build a virtual directory tree from member paths."""
    root: dict[str, object] = {"name": Path(name).name, "children": [], "size": 0}
    nodes: dict[str, dict[str, object]] = {"": root}
    needle = str(prefix).strip("/") if prefix else ""
    limit = int(depth) if isinstance(depth, int) else None
    for member in members:
        path = member.normalised_path.strip("/")
        if needle and path != needle and not path.startswith(needle + "/"):
            continue
        relative = path[len(needle) + 1 :] if needle and path.startswith(needle + "/") else path
        if needle and path == needle:
            relative = Path(path).name
        parts = [part for part in relative.split("/") if part not in {"", "."}]
        if directories_only and member.member_type != "directory":
            parts = parts[:-1]
        if limit is not None:
            parts = parts[:limit]
        parent = ""
        for index, part in enumerate(parts):
            key = f"{parent}/{part}" if parent else part
            is_leaf = index == len(parts) - 1
            if key not in nodes:
                node: dict[str, object] = {
                    "name": part
                    + ("/" if not is_leaf or member.member_type == "directory" else ""),
                    "children": [],
                    "size": member.size if is_leaf else 0,
                    "type": member.member_type if is_leaf else "directory",
                    "inferred": not is_leaf or member.inferred,
                }
                if is_leaf and member.nested_format:
                    node["nested_format"] = member.nested_format
                nodes[key] = node
                children = nodes[parent]["children"]
                if isinstance(children, list):
                    children.append(node)
            parent = key
    if sizes:
        _aggregate(root)
    _sort_nodes(root)
    return root


def _aggregate(node: dict[str, object]) -> int:
    children = node.get("children")
    total = 0
    if isinstance(children, list):
        for child in children:
            if isinstance(child, dict):
                total += _aggregate(child)
    own = node.get("size")
    if isinstance(own, int) and not children:
        total = own
    node["size"] = total
    return total


def _sort_nodes(node: dict[str, object]) -> None:
    children = node.get("children")
    if not isinstance(children, list):
        return
    children.sort(
        key=lambda item: str(item.get("name", "")).casefold() if isinstance(item, dict) else ""
    )
    for child in children:
        if isinstance(child, dict):
            _sort_nodes(child)


def run_tree(ctx: Context, path: Path, args: object) -> int:
    """Show a virtual directory tree."""
    session = _root(ctx, path)
    members = session.list_members()
    sniff_nested(session, members, ctx.budget)
    root = _tree(
        session.display_path,
        members,
        depth=_opt(args, "depth"),
        directories_only=bool(_opt(args, "directories_only")),
        sizes=bool(_opt(args, "sizes")),
        prefix=_opt(args, "path"),
    )
    payload = envelope("tree", "completed", archive={"path": session.display_path}, tree=root)
    ctx.emit(payload, tree_text(root, sizes=bool(_opt(args, "sizes"))))
    return ExitCode.OK


def run_find(ctx: Context, path: Path, args: object) -> int:
    """Find members by attribute."""
    session = _root(ctx, path)
    errors: list[str] = []
    listed = list(
        _descendants(ctx, session, errors) if _opt(args, "nested") else session.list_members()
    )
    source: list[Member] = [*listed, *inferred_directories(listed)]
    matched = [item for item in source if _matches(item, args)]
    records = [item.to_dict() for item in matched]
    payload = envelope(
        "find",
        "partial" if errors else "completed",
        match_count=len(records),
        members=records,
        errors=errors,
    )
    ctx.emit(payload, member_lines(records, long=True), records)
    if errors:
        return ExitCode.PARTIAL
    if not records and _opt(args, "fail_on_empty"):
        return ExitCode.FAILURE
    return ExitCode.OK


def run_grep(ctx: Context, path: Path, args: object) -> int:
    """Search text inside archive members."""
    session = _root(ctx, path)
    pattern = str(_opt(args, "pattern"))
    if len(pattern) > 1024:
        raise AppError("search pattern is too long", ExitCode.USAGE)
    matcher = _matcher(pattern, bool(_opt(args, "regex")), bool(_opt(args, "ignore_case")))
    errors: list[str] = []
    source: Iterable[Member] = (
        _descendants(ctx, session, errors) if _opt(args, "nested") else session.list_members()
    )
    records: list[dict[str, object]] = []
    failures: list[dict[str, object]] = []
    for member in source:
        if member.member_type != "file":
            continue
        name = Path(member.normalised_path).name
        include = _opt(args, "include")
        exclude = _opt(args, "exclude")
        if include and not fnmatch.fnmatchcase(name, str(include)):
            continue
        if exclude and fnmatch.fnmatchcase(name, str(exclude)):
            continue
        owner = _owner(ctx, session, member)
        try:
            records.extend(
                _search_member(
                    ctx,
                    owner,
                    member,
                    matcher,
                    str(_opt(args, "encoding") or ctx.settings.default_encoding),
                    str(_opt(args, "encoding_errors") or ctx.settings.encoding_errors),
                    bool(_opt(args, "binary")),
                    _required_int(_opt(args, "context")),
                    bool(_opt(args, "count")),
                    bool(_opt(args, "files_with_matches")),
                )
            )
        except AppError as exc:
            failures.append(
                {"member": member.virtual_path(), "message": exc.message, "code": exc.code}
            )
    status = "partial" if failures or errors else "completed"
    payload = envelope(
        "grep", status, match_count=len(records), matches=records, errors=failures + errors
    )
    if _opt(args, "count") or _opt(args, "files_with_matches"):
        text = "".join(f"{item['path']}:{item['count']}\n" for item in records)
    else:
        text = "".join(
            escape_terminal(f"{item['path']}:{item.get('line', '')}:{item.get('text', '')}") + "\n"
            for item in records
        )
    ctx.emit(payload, text, records)
    if failures:
        return ExitCode.PARTIAL
    if not records and _opt(args, "fail_on_empty"):
        return ExitCode.FAILURE
    return ExitCode.OK


def run_cat(ctx: Context, path: Path, args: object) -> int:
    """Stream one member to standard output."""
    session, member = resolve_chain(
        path,
        _segments(args),
        password=ctx.password,
        archive_format=ctx.archive_format,
        force=ctx.force,
        budget=ctx.budget,
        workspace=ctx.workspace,
        sessions=ctx.sessions,
    )
    member = _follow(session, member, ctx)
    if member.member_type != "file":
        raise AppError(f"{member.path} is not a regular file", ExitCode.UNSUPPORTED)
    interactive = bool(getattr(ctx.stdout, "isatty", lambda: False)())
    if interactive and not ctx.force:
        with session.open_member(member, ctx.budget, stop_at=8192) as probe:
            sample = probe.read(8192)
        if looks_binary(sample):
            raise AppError(
                "refusing to write binary data to a terminal without --force", ExitCode.USAGE
            )
    with session.open_member(member, ctx.budget) as reader:
        while True:
            chunk = reader.read(1024 * 1024)
            if not chunk:
                break
            try:
                ctx.stdout.write(chunk)
            except BrokenPipeError:
                return ExitCode.OK
    try:
        ctx.stdout.flush()
    except BrokenPipeError:
        return ExitCode.OK
    return ExitCode.OK


def run_get(ctx: Context, path: Path, args: object) -> int:
    """Extract selected members."""
    session = _root(ctx, path)
    chosen = _choose(ctx, session, args)
    output = _opt(args, "output_file")
    dest = _opt(args, "dest")
    dry_run = bool(_opt(args, "dry_run"))
    if len(chosen) == 1 and output and not dest:
        return _one_file(ctx, chosen[0][0], chosen[0][1], Path(str(output)), dry_run)
    if dest is None:
        raise AppError("extracting more than one member needs --dest", ExitCode.USAGE)
    root = Path(str(dest))
    root.mkdir(parents=True, exist_ok=True)
    failures = 0
    written: list[str] = []
    for owner, member in chosen:
        try:
            target = _extract(
                ctx,
                owner,
                member,
                root,
                flatten=bool(_opt(args, "flatten")),
                dry_run=dry_run,
                allow_symlinks=bool(_opt(args, "allow_symlinks")),
                allow_hardlinks=bool(_opt(args, "allow_hardlinks")),
            )
            if target is not None:
                written.append(str(target))
        except AppError as exc:
            failures += 1
            ctx.stderr.write(exc.message + "\n")
    status = "completed" if not failures else "partial"
    ctx.emit(
        envelope("get", status, extracted=written, failures=failures),
        "".join(f"{item}\n" for item in written),
    )
    if failures and failures == len(chosen):
        return ExitCode.SAFETY
    if failures:
        return ExitCode.PARTIAL
    return ExitCode.OK


def run_diff(ctx: Context, old: Path, new: Path, args: object) -> int:
    """Compare two archives."""
    mode = str(_opt(args, "mode") or "fast")
    left = _root(ctx, old)
    right = _root(ctx, new)
    errors: list[str] = []
    left_members = _descendants(ctx, left, errors) if _opt(args, "nested") else left.list_members()
    right_members = (
        _descendants(ctx, right, errors) if _opt(args, "nested") else right.list_members()
    )
    payload = _compare(
        ctx,
        left,
        right,
        list(left_members),
        list(right_members),
        mode,
        bool(_opt(args, "ignore_case_paths")),
        args,
    )
    ctx.emit(payload, diff_text(payload))
    return ExitCode.PARTIAL if errors else ExitCode.OK


def run_duplicates(ctx: Context, paths: Sequence[Path], args: object) -> int:
    """Find byte-for-byte duplicate files."""
    algorithm = str(_opt(args, "hash_algorithm") or "sha256")
    if algorithm != "sha256":
        raise AppError("only sha256 is supported", ExitCode.UNSUPPORTED)
    grouped: dict[int, list[tuple[ArchiveSession, Member]]] = defaultdict(list)
    errors: list[str] = []
    for path in paths:
        session = _root(ctx, path)
        source: Iterable[Member] = (
            _descendants(ctx, session, errors) if _opt(args, "nested") else session.list_members()
        )
        for member in source:
            if member.member_type == "file" and member.size:
                grouped[member.size].append((_owner(ctx, session, member), member))
    groups: list[dict[str, object]] = []
    for size, items in grouped.items():
        if len(items) < 2:
            continue
        by_hash: dict[str, list[Member]] = defaultdict(list)
        for owner, member in items:
            digest = hash_member(owner, member, ctx.budget)
            if digest:
                by_hash[digest].append(member)
        for digest, members in by_hash.items():
            if len(members) < 2:
                continue
            groups.append(
                {
                    "hash": f"sha256:{digest}",
                    "size": size,
                    "occurrences": len(members),
                    "redundant_uncompressed_bytes": size * (len(members) - 1),
                    "estimated_archive_savings": None,
                    "members": [item.virtual_path() for item in members],
                }
            )
    payload = envelope(
        "duplicates",
        "partial" if errors else "completed",
        groups=groups,
        limitations=[
            "Archive storage savings are unavailable unless the format exposes them reliably."
        ],
        errors=errors,
    )
    ctx.emit(payload, duplicates_text(payload), groups)
    return ExitCode.PARTIAL if errors else ExitCode.OK


def run_nested(ctx: Context, path: Path, depth: int | None) -> int:
    """List nested archives."""
    session = _root(ctx, path)
    errors: list[str] = []
    found = []
    limit = depth or ctx.budget.limits.max_depth or 1
    for member in iter_nested(
        session,
        budget=ctx.budget,
        workspace=ctx.workspace,
        password=ctx.password,
        force=ctx.force,
        max_depth=limit,
        sessions=ctx.sessions,
        errors=errors,
    ):
        if member.nested_format:
            found.append(member.to_dict())
    payload = envelope(
        "nested",
        "partial" if errors else "completed",
        archives=found,
        count=len(found),
        errors=errors,
    )
    text = (
        "".join(f"{item['virtual_path']} {item['nested_format']}\n" for item in found)
        or "No nested archives.\n"
    )
    ctx.emit(payload, text, found)
    return ExitCode.PARTIAL if errors else ExitCode.OK


def run_safety(ctx: Context, path: Path, *, nested: bool) -> int:
    """Assess extraction risk."""
    session = _root(ctx, path)
    members = list(session.list_members())
    errors: list[str] = []
    depth = 1
    if nested:
        for item in _descendants(ctx, session, errors):
            if item.nesting_level:
                members.append(item)
                depth = max(depth, item.nesting_level + 1)
    findings = analyse(
        members,
        compressed_size=session.path.stat().st_size,
        limits=ctx.budget.limits,
        nested_depth=depth,
    )
    payload = envelope(
        "safety",
        "completed",
        findings=[item.to_dict() for item in findings],
        limitations=[
            "A safety scan does not detect malware and does not prove an archive is safe."
        ],
        errors=errors,
    )
    ctx.emit(
        payload, findings_text(payload, colour=ctx.colour), [item.to_dict() for item in findings]
    )
    return ExitCode.OK


def run_test(ctx: Context, path: Path, *, full: bool, nested: bool) -> int:
    """Test archive integrity."""
    session = _root(ctx, path)
    errors: list[str] = []
    targets = list(_descendants(ctx, session, errors) if nested else session.list_members())
    counts = {"passed": 0, "failed": 0, "skipped": 0, "unsupported": 0}
    failures: list[dict[str, object]] = []
    for member in targets:
        owner = _owner(ctx, session, member)
        if not full:
            outcome = (
                "unsupported"
                if member.compression and str(member.compression).startswith("unsupported")
                else "passed"
            )
            if member.member_type == "other":
                outcome = "unsupported"
        else:
            outcome = owner.test_member(member, ctx.budget)
        counts[outcome] += 1
        if outcome == "failed":
            failures.append({"member": member.virtual_path(), "message": "integrity check failed"})
    if counts["failed"]:
        overall, code = "failed", ExitCode.CORRUPT
    elif counts["unsupported"] and not counts["passed"]:
        overall, code = "unsupported", ExitCode.UNSUPPORTED
    elif errors or (counts["skipped"] and not counts["passed"]):
        overall, code = "incomplete", ExitCode.PARTIAL
    else:
        overall, code = "passed", ExitCode.OK
    verification = (
        "Full mode decompresses regular files and checks stored checksums when present."
        if full
        else "Structural mode validates accessible metadata. Member bytes were not recomputed."
    )
    if not any(item.checksum_algorithm for item in targets):
        verification += " This format did not expose stored member checksums."
    payload = envelope(
        "test",
        overall,
        outcome=overall,
        tested=len(targets),
        passed=counts["passed"],
        failed=counts["failed"],
        skipped=counts["skipped"],
        unsupported=counts["unsupported"],
        errors=failures,
        verification=verification,
        limitations=list(session.limitations) + errors,
    )
    ctx.emit(payload, test_text(payload))
    return code


def run_report(ctx: Context, path: Path, *, full: bool, nested: bool) -> int:
    """Build one report covering summary, safety, and integrity."""
    session = _root(ctx, path)
    errors: list[str] = []
    members = list(_descendants(ctx, session, errors) if nested else session.list_members())
    if not nested:
        sniff_nested(session, members, ctx.budget)
    summary = archive_summary(session, members)
    findings = analyse(
        members, compressed_size=session.path.stat().st_size, limits=ctx.budget.limits
    )
    counts = {"passed": 0, "failed": 0, "skipped": 0, "unsupported": 0}
    for member in members:
        owner = _owner(ctx, session, member)
        if not full:
            outcome = (
                "unsupported"
                if str(member.compression or "").startswith("unsupported")
                else "passed"
            )
        else:
            outcome = owner.test_member(member, ctx.budget)
        counts[outcome] += 1
    groups = _duplicate_groups(ctx, session, members)
    payload = envelope(
        "report",
        "partial" if errors or counts["failed"] else "completed",
        archive=summary,
        warnings=[item.to_dict() for item in findings],
        integrity={
            "mode": "full" if full else "structural",
            "passed": counts["passed"],
            "failed": counts["failed"],
            "skipped": counts["skipped"],
            "unsupported": counts["unsupported"],
        },
        integrity_outcome="full" if full else "structural",
        duplicates=groups,
        nested=nested,
        limitations=list(session.limitations) + errors,
    )
    text = inspect_text(payload, colour=ctx.colour) + findings_text(payload, colour=ctx.colour)
    text += (
        f"\nIntegrity ({payload['integrity_outcome']}): "
        f"{counts['passed']} passed, {counts['failed']} failed\n"
    )
    text += f"Duplicate groups: {len(groups)}\n"
    ctx.emit(payload, text, [item.to_dict() for item in findings])
    if counts["failed"]:
        return ExitCode.CORRUPT
    return ExitCode.PARTIAL if errors else ExitCode.OK


def _duplicate_groups(
    ctx: Context, session: ArchiveSession, members: list[Member]
) -> list[dict[str, object]]:
    grouped: dict[int, list[Member]] = defaultdict(list)
    for member in members:
        if member.member_type == "file" and member.size:
            grouped[member.size].append(member)
    groups: list[dict[str, object]] = []
    for size, items in grouped.items():
        if len(items) < 2:
            continue
        by_hash: dict[str, list[str]] = defaultdict(list)
        for member in items:
            digest = hash_member(_owner(ctx, session, member), member, ctx.budget)
            if digest:
                by_hash[digest].append(member.virtual_path())
        for digest, paths in by_hash.items():
            if len(paths) < 2:
                continue
            groups.append(
                {
                    "hash": f"sha256:{digest}",
                    "size": size,
                    "occurrences": len(paths),
                    "redundant_uncompressed_bytes": size * (len(paths) - 1),
                    "estimated_archive_savings": None,
                    "members": paths,
                }
            )
    return groups


def run_formats(ctx: Context) -> int:
    """Show runtime format capabilities."""
    rows = [item.to_dict() for item in capabilities()]
    payload = envelope("formats", "completed", formats=rows)
    ctx.emit(payload, formats_text(payload), rows)
    return ExitCode.OK


def run_version(ctx: Context, version: str) -> int:
    """Show version information."""
    payload = envelope(
        "version",
        "completed",
        version=version,
        python=sys.version.split()[0],
        platform=sys.platform,
    )
    ctx.emit(payload, f"archive-explorer {version}\nPython {payload['python']}\n{sys.platform}\n")
    return ExitCode.OK


def release(ctx: Context) -> None:
    """Close archives and remove temporary files."""
    close_sessions(ctx.sessions)
    ctx.workspace.close()
    try:
        ctx.workspace.directory.rmdir()
    except OSError:
        return


def _root(ctx: Context, path: Path) -> ArchiveSession:
    session = open_archive(
        path, password=ctx.password, archive_format=ctx.archive_format, force=ctx.force
    )
    ctx.sessions.append(session)
    return session


def _subject(ctx: Context, path: Path, member: str | None) -> tuple[ArchiveSession, list[Member]]:
    if not member:
        session = _root(ctx, path)
        return session, session.list_members()
    session, selected = resolve_chain(
        path,
        parse_virtual_path(member),
        password=ctx.password,
        archive_format=ctx.archive_format,
        force=ctx.force,
        budget=ctx.budget,
        workspace=ctx.workspace,
        sessions=ctx.sessions,
    )
    spilled = ctx.workspace.spill(session.open_member(selected, ctx.budget))
    nested = open_archive(
        spilled, display_path=selected.virtual_path(), password=ctx.password, force=ctx.force
    )
    nested.materialised = True
    ctx.sessions.append(nested)
    return nested, nested.list_members()


def _descendants(ctx: Context, session: ArchiveSession, errors: list[str]) -> Iterable[Member]:
    return iter_nested(
        session,
        budget=ctx.budget,
        workspace=ctx.workspace,
        password=ctx.password,
        force=ctx.force,
        max_depth=ctx.budget.limits.max_depth or 1,
        sessions=ctx.sessions,
        errors=errors,
    )


def _owner(ctx: Context, root: ArchiveSession, member: Member) -> ArchiveSession:
    if member.archive_path == root.display_path:
        return root
    for session in ctx.sessions:
        if session.display_path == member.archive_path:
            return session
    return root


def _under(members: list[Member], prefix: object) -> list[Member]:
    if not prefix:
        return list(members)
    text = str(prefix).replace("\\", "/").rstrip("/")
    return [
        member
        for member in members
        if member.normalised_path.rstrip("/") == text
        or member.normalised_path.startswith(text + "/")
    ]


def _sort(members: list[Member], key: object, descending: bool) -> list[Member]:
    name = str(key or "name")

    def sort_key(member: Member) -> tuple[object, ...]:
        if name == "size":
            return (member.size is None, -(member.size or 0) if descending else member.size or 0)
        if name == "date":
            stamp = member.mtime.timestamp() if member.mtime else None
            return (stamp is None, -(stamp or 0) if descending else stamp or 0)
        if name == "type":
            return (member.member_type, member.normalised_path)
        if name == "ratio" and member.size and member.compressed_size:
            ratio = member.size / max(member.compressed_size, 1)
            return (False, -ratio if descending else ratio)
        if name == "ratio":
            return (True, 0)
        return (
            member.normalised_path.casefold() if descending else member.normalised_path,
            member.occurrence,
        )

    reverse = descending and name == "name"
    return sorted(members, key=sort_key, reverse=reverse)


def _matches(member: Member, args: object) -> bool:
    checks: list[bool] = []
    pattern = _opt(args, "pattern")
    ignore_case = bool(_opt(args, "ignore_case"))
    full = bool(_opt(args, "full_path")) or (pattern is not None and "/" in str(pattern))
    target = member.normalised_path if full else Path(member.normalised_path).name
    if pattern:
        if _opt(args, "regex"):
            flags = re.IGNORECASE if ignore_case else 0
            try:
                checks.append(re.search(str(pattern), target, flags) is not None)
            except re.error as exc:
                raise AppError(f"invalid regular expression: {exc}", ExitCode.USAGE) from exc
        else:
            pat = str(pattern).casefold() if ignore_case else str(pattern)
            hay = target.casefold() if ignore_case else target
            checks.append(fnmatch.fnmatchcase(hay, pat))
    if _opt(args, "entry_type"):
        checks.append(member.member_type == _opt(args, "entry_type"))
    if _opt(args, "min_size") is not None:
        checks.append(
            member.size is not None and member.size >= _required_int(_opt(args, "min_size"))
        )
    if _opt(args, "max_size_filter") is not None:
        checks.append(
            member.size is not None and member.size <= _required_int(_opt(args, "max_size_filter"))
        )
    after = _opt(args, "modified_after")
    before = _opt(args, "modified_before")
    if isinstance(after, datetime):
        checks.append(member.mtime is not None and member.mtime.date() >= after.date())
    if isinstance(before, datetime):
        checks.append(member.mtime is not None and member.mtime.date() <= before.date())
    if _opt(args, "compression"):
        checks.append(
            bool(member.compression)
            and str(_opt(args, "compression")).lower() in str(member.compression).lower()
        )
    if _opt(args, "encrypted"):
        checks.append(member.encrypted is True)
    if _opt(args, "not_encrypted"):
        checks.append(member.encrypted is False)
    if not checks:
        return True
    return any(checks) if str(_opt(args, "match") or "all") == "any" else all(checks)


def _matcher(pattern: str, regex: bool, ignore_case: bool) -> Callable[[str], bool]:
    flags = re.IGNORECASE if ignore_case else 0
    if regex:
        try:
            compiled = re.compile(pattern, flags)
        except re.error as exc:
            raise AppError(f"invalid regular expression: {exc}", ExitCode.USAGE) from exc
        return lambda line: compiled.search(line) is not None
    needle = pattern.casefold() if ignore_case else pattern

    def literal(line: str) -> bool:
        return needle in (line.casefold() if ignore_case else line)

    return literal


def _search_member(
    ctx: Context,
    session: ArchiveSession,
    member: Member,
    matcher: Callable[[str], bool],
    encoding: str,
    policy: str,
    binary: bool,
    context: int,
    count_only: bool,
    names_only: bool,
) -> list[dict[str, object]]:
    chunks: list[bytes] = []
    with session.open_member(member, ctx.budget) as reader:
        sample = reader.read(8192)
        if not binary and looks_binary(sample):
            return []
        chunks.append(sample)
        while True:
            chunk = reader.read(65536)
            if not chunk:
                break
            chunks.append(chunk)
            ctx.budget.check_time()
    data = b"".join(chunks)
    if binary:
        text = data.decode(encoding, errors="replace")
        return (
            [{"path": member.virtual_path(), "line": 0, "text": "[binary match]"}]
            if matcher(text)
            else []
        )
    lines = data.decode(encoding, errors=policy).splitlines()
    hits = []
    for number, line in enumerate(lines, start=1):
        if len(line) > ctx.budget.limits.max_line_length:
            line = line[: ctx.budget.limits.max_line_length]
            ctx.warn(f"{member.virtual_path()}:{number}: line truncated")
        if matcher(line):
            hits.append(number)
    if not hits:
        return []
    if count_only or names_only:
        return [{"path": member.virtual_path(), "count": len(hits)}]
    shown: set[int] = set()
    records: list[dict[str, object]] = []
    for number in hits:
        for current in range(max(1, number - context), min(len(lines), number + context) + 1):
            if current in shown:
                continue
            shown.add(current)
            records.append(
                {
                    "path": member.virtual_path(),
                    "line": current,
                    "text": lines[current - 1][: ctx.budget.limits.max_line_length],
                    "match": current in hits,
                }
            )
    return records


def looks_binary(sample: bytes) -> bool:
    """Return whether a prefix looks like non-text data."""
    if b"\x00" in sample:
        return True
    return any(byte < 32 and byte not in (9, 10, 13) for byte in sample)


def _segments(args: object) -> list[Segment]:
    selector = _opt(args, "selector")
    virtual = _opt(args, "path")
    index = _opt(args, "index")
    if selector and (virtual or index):
        raise AppError("use either --selector or --path/--index", ExitCode.USAGE)
    if selector:
        return parse_selector_json(str(selector))
    if index and virtual:
        raise AppError("use either --path or --index", ExitCode.USAGE)
    if index:
        return [Segment(index=_required_int(index))]
    if virtual:
        return parse_virtual_path(str(virtual))
    raise AppError("a member --path, --index, or --selector is required", ExitCode.USAGE)


def _follow(session: ArchiveSession, member: Member, ctx: Context) -> Member:
    seen: set[str] = set()
    current = member
    while current.member_type == "symlink":
        if not ctx.follow_symlinks:
            raise AppError(
                f"{current.path} is a symbolic link to "
                f"{current.link_target or 'an unspecified target'}",
                ExitCode.UNSUPPORTED,
            )
        target = current.link_target or ""
        if not target or is_absolute_member(target) or has_traversal(target) or target in seen:
            raise AppError("refusing to follow an unsafe or cyclic symbolic link", ExitCode.SAFETY)
        seen.add(target)
        current = select_member(session.list_members(), Segment(path=target))
    return current


def _choose(
    ctx: Context, session: ArchiveSession, args: object
) -> list[tuple[ArchiveSession, Member]]:
    selected: list[tuple[ArchiveSession, Member]] = []
    if _opt(args, "index"):
        selected.append(
            (
                session,
                select_member(
                    session.list_members(), Segment(index=_required_int(_opt(args, "index")))
                ),
            )
        )
    for virtual in _strings(_opt(args, "paths")):
        segments = parse_virtual_path(str(virtual))
        if len(segments) == 1:
            selected.append((session, select_member(session.list_members(), segments[0])))
            continue
        owner, member = resolve_chain(
            session.path,
            segments,
            password=ctx.password,
            archive_format=ctx.archive_format,
            force=ctx.force,
            budget=ctx.budget,
            workspace=ctx.workspace,
            sessions=ctx.sessions,
        )
        selected.append((owner, member))
    for pattern in _strings(_opt(args, "globs")):
        for member in session.list_members():
            if fnmatch.fnmatchcase(member.normalised_path, str(pattern)) or fnmatch.fnmatchcase(
                Path(member.normalised_path).name, str(pattern)
            ):
                selected.append((session, member))
    if not selected:
        raise AppError("no members selected", ExitCode.NOT_FOUND)
    return selected


def _one_file(
    ctx: Context, session: ArchiveSession, member: Member, output: Path, dry_run: bool
) -> int:
    if member.member_type != "file":
        raise AppError("a single --output path can only receive a regular file", ExitCode.USAGE)
    if output.is_symlink():
        raise AppError("refusing to write through a symlink", ExitCode.SAFETY)
    if output.exists() and not ctx.force:
        raise AppError(f"output already exists: {output}", ExitCode.FAILURE)
    if not dry_run:
        output.parent.mkdir(parents=True, exist_ok=True)
        _stream_file(session, member, output, ctx)
    ctx.emit(envelope("get", "completed", extracted=[str(output)]), f"{output}\n")
    return ExitCode.OK


def _extract(
    ctx: Context,
    session: ArchiveSession,
    member: Member,
    root: Path,
    *,
    flatten: bool,
    dry_run: bool,
    allow_symlinks: bool,
    allow_hardlinks: bool,
) -> Path | None:
    if member.member_type == "other":
        raise AppError(f"refusing special file {member.path}", ExitCode.UNSUPPORTED)
    if member.member_type == "symlink" and not allow_symlinks:
        raise AppError(
            f"refusing symbolic link {member.path} without --allow-symlinks", ExitCode.SAFETY
        )
    if member.member_type == "hardlink" and not allow_hardlinks:
        raise AppError(
            f"refusing hard link {member.path} without --allow-hardlinks", ExitCode.SAFETY
        )
    relative = Path(member.normalised_path).name if flatten else member.normalised_path
    target = confine(root, relative)
    if member.member_type == "directory":
        if not dry_run:
            target.mkdir(parents=True, exist_ok=True)
        return target
    if member.member_type == "symlink":
        link_target = member.link_target or ""
        confine(root, str(Path(relative).parent / link_target))
        if not dry_run:
            target.parent.mkdir(parents=True, exist_ok=True)
            if target.exists() or target.is_symlink():
                if not ctx.force:
                    raise AppError(f"output already exists: {target}", ExitCode.FAILURE)
                target.unlink()
            os.symlink(link_target, target)
        return target
    if target.exists() and not ctx.force:
        raise AppError(f"output already exists: {target}", ExitCode.FAILURE)
    if dry_run:
        return target
    target.parent.mkdir(parents=True, exist_ok=True)
    if member.member_type == "hardlink":
        source = confine(root, member.link_target or "")
        if not source.is_file():
            raise AppError(
                "hard link target is not an extracted file inside the destination", ExitCode.SAFETY
            )
        os.link(source, target)
        return target
    _stream_file(session, member, target, ctx)
    return target


def _stream_file(session: ArchiveSession, member: Member, target: Path, ctx: Context) -> None:
    descriptor, temporary = tempfile.mkstemp(dir=target.parent, prefix=".archive-explorer-")
    temporary_path = Path(temporary)
    try:
        with (
            os.fdopen(descriptor, "wb") as handle,
            session.open_member(member, ctx.budget) as reader,
        ):
            while True:
                chunk = reader.read(1024 * 1024)
                if not chunk:
                    break
                handle.write(chunk)
        os.chmod(temporary_path, 0o600)
        os.replace(temporary_path, target)
    except Exception:
        temporary_path.unlink(missing_ok=True)
        raise


def _compare(
    ctx: Context,
    left_session: ArchiveSession,
    right_session: ArchiveSession,
    left_members: list[Member],
    right_members: list[Member],
    mode: str,
    ignore_case: bool,
    args: object,
) -> dict[str, object]:
    def key(member: Member) -> tuple[str, int]:
        path = member.normalised_path.casefold() if ignore_case else member.normalised_path
        return path, member.occurrence

    left_map = {key(member): member for member in left_members}
    right_map = {key(member): member for member in right_members}
    added: list[dict[str, object]] = []
    removed: list[dict[str, object]] = []
    modified: list[dict[str, object]] = []
    type_changed: list[dict[str, object]] = []
    metadata_changed: list[dict[str, object]] = []
    indeterminate: list[dict[str, object]] = []
    unchanged = 0
    text_diffs: list[dict[str, object]] = []
    for item_key in sorted(set(left_map) | set(right_map)):
        left = left_map.get(item_key)
        right = right_map.get(item_key)
        if left is None and right is not None:
            added.append({"path": right.virtual_path()})
            continue
        if right is None and left is not None:
            removed.append({"path": left.virtual_path()})
            continue
        if left is None or right is None:
            continue
        if left.member_type != right.member_type:
            type_changed.append({"path": right.virtual_path()})
            continue
        meta = (
            left.size != right.size
            or left.mtime != right.mtime
            or left.permissions != right.permissions
        )
        checksums_differ = (
            left.checksum_value is not None
            and right.checksum_value is not None
            and left.checksum_value != right.checksum_value
        )
        if mode == "fast":
            if checksums_differ or left.size != right.size:
                modified.append({"path": right.virtual_path()})
            elif meta:
                metadata_changed.append({"path": right.virtual_path()})
            else:
                unchanged += 1
            continue
        if left.member_type != "file":
            if meta:
                metadata_changed.append({"path": right.virtual_path()})
            else:
                unchanged += 1
            continue
        try:
            left_hash = hash_member(_owner(ctx, left_session, left), left, ctx.budget)
            right_hash = hash_member(_owner(ctx, right_session, right), right, ctx.budget)
        except AppError:
            indeterminate.append({"path": right.virtual_path()})
            continue
        if left_hash != right_hash:
            modified.append({"path": right.virtual_path()})
            if mode == "detailed":
                diff = _textual(ctx, left_session, right_session, left, right, args)
                if diff:
                    text_diffs.append({"path": right.virtual_path(), "diff": diff})
        elif meta:
            metadata_changed.append({"path": right.virtual_path()})
        else:
            unchanged += 1
    note = None
    if mode == "fast":
        note = (
            "Fast mode compares paths, types, declared sizes, timestamps, and stored checksums. "
            "It does not prove byte-for-byte equality."
        )
    return envelope(
        "diff",
        "completed",
        mode=mode,
        added=added,
        removed=removed,
        modified=modified,
        type_changed=type_changed,
        metadata_changed=metadata_changed,
        indeterminate=indeterminate,
        unchanged=unchanged,
        text_diffs=text_diffs,
        note=note,
    )


def _textual(
    ctx: Context,
    left_session: ArchiveSession,
    right_session: ArchiveSession,
    left: Member,
    right: Member,
    args: object,
) -> str | None:
    limit = ctx.budget.limits.max_diff_bytes
    if (left.size or 0) > limit or (right.size or 0) > limit:
        return None
    left_bytes = _read_all(_owner(ctx, left_session, left), left, ctx)
    right_bytes = _read_all(_owner(ctx, right_session, right), right, ctx)
    if looks_binary(left_bytes[:8192]) or looks_binary(right_bytes[:8192]):
        return None
    encoding = ctx.settings.default_encoding
    left_text = left_bytes.decode(encoding, errors="replace")
    right_text = right_bytes.decode(encoding, errors="replace")
    if _opt(args, "ignore_whitespace"):
        left_text = re.sub(r"\s+", " ", left_text)
        right_text = re.sub(r"\s+", " ", right_text)
    diff = difflib.unified_diff(
        left_text.splitlines(),
        right_text.splitlines(),
        fromfile=left.virtual_path(),
        tofile=right.virtual_path(),
        n=_required_int(_opt(args, "context"), 3),
        lineterm="",
    )
    return "\n".join(diff)


def _read_all(session: ArchiveSession, member: Member, ctx: Context) -> bytes:
    chunks: list[bytes] = []
    with session.open_member(member, ctx.budget) as reader:
        while True:
            chunk = reader.read(1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
    return b"".join(chunks)


def _opt(args: object, name: str) -> object:
    return getattr(args, name, None)


def _required_int(value: object, default: int = 0) -> int:
    """Return an integer option, or ``default`` when it was omitted."""
    if value is None:
        return default
    if isinstance(value, bool) or not isinstance(value, int):
        raise AppError("expected an integer option", ExitCode.USAGE)
    return value


def _strings(value: object) -> list[str]:
    """Return a list of strings from a repeated option."""
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item) for item in value]
    return [str(value)]


def _as_int(value: object) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value


# write_atomic is re-exported for tests that patch output.
_ = write_atomic
