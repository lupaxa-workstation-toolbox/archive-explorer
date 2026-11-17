"""Text, JSON, Markdown, and HTML rendering."""

from __future__ import annotations

import html
import json
from typing import TextIO

from lupaxa.archive_explorer.human import format_bytes, format_count, format_percent
from lupaxa.archive_explorer.models import SCHEMA_VERSION

_RESET = "\033[0m"
_YELLOW = "\033[33m"
_RED = "\033[31m"


def dumps(payload: dict[str, object]) -> str:
    """Serialise one JSON document."""
    return json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=False) + "\n"


def dumps_lines(payload: dict[str, object], records: list[dict[str, object]]) -> str:
    """Serialise a summary line followed by one JSON object per record."""
    lines = [json.dumps({"type": "summary", **_without(payload, "records")}, ensure_ascii=False)]
    lines.extend(json.dumps(record, ensure_ascii=False) for record in records)
    return "\n".join(lines) + "\n"


def _without(payload: dict[str, object], key: str) -> dict[str, object]:
    return {name: value for name, value in payload.items() if name != key}


def escape_terminal(text: str) -> str:
    """Make untrusted text safe for a terminal."""
    parts: list[str] = []
    for char in text:
        code = ord(char)
        if char == "\t" or char == "\n":
            parts.append(char)
        elif code < 32 or code == 127:
            parts.append(f"\\x{code:02x}")
        else:
            parts.append(char)
    return "".join(parts)


def paint(text: str, colour: str, enabled: bool) -> str:
    """Colour ``text`` when colour is enabled."""
    if not enabled:
        return text
    return f"{colour}{text}{_RESET}"


def envelope(command: str, status: str, **fields: object) -> dict[str, object]:
    """Return a schema document."""
    payload: dict[str, object] = {
        "schema_version": SCHEMA_VERSION,
        "command": command,
        "status": status,
    }
    payload.update(fields)
    return payload


def write_text(handle: TextIO, text: str) -> None:
    """Write text, turning a broken pipe into a clean stop."""
    try:
        handle.write(text)
        handle.flush()
    except BrokenPipeError:
        raise


def inspect_text(payload: dict[str, object], *, colour: bool) -> str:
    """Render a human inspect report."""
    archive = payload["archive"]
    archive = _as_dict(archive)
    lines = [
        "Archive Explorer",
        "",
        f"Archive: {archive['path']}",
        f"Format: {str(archive['format']).upper()}",
        f"Compressed size: {format_bytes(_int_or_none(archive.get('compressed_size')))}",
        "Uncompressed size: "
        + format_bytes(_int_or_none(archive.get("declared_uncompressed_size"))),
        "",
        "Members:",
        f"  Files:       {format_count(_count(archive['file_count']))}",
        f"  Directories: {format_count(_count(archive['directory_count']))}",
        f"  Symlinks:    {format_count(_count(archive['symlink_count']))}",
        "",
        "Compression saving: " + format_percent(_float_or_none(archive.get("compression_saving"))),
        f"Backend: {archive['backend']} {archive['backend_version']}",
        f"Encrypted: {_yes_no(archive.get('encrypted'))}",
        f"Nested archives: {payload.get('nested_archive_count', 0)}",
    ]
    earliest = payload.get("earliest_mtime")
    latest = payload.get("latest_mtime")
    if earliest or latest:
        lines.append(f"Modified: {earliest or 'unavailable'} to {latest or 'unavailable'}")
    largest = payload.get("largest_directories") or []
    if isinstance(largest, list) and largest:
        lines.extend(["", "Largest directories:"])
        for item in largest:
            item = _as_dict(item)
            lines.append(f"  {item['path']:<16} {format_bytes(_int_or_none(item.get('size')))}")
    members = payload.get("largest_members") or []
    if isinstance(members, list) and members:
        lines.extend(["", "Largest members:"])
        for item in members:
            item = _as_dict(item)
            lines.append(f"  {item['path']:<16} {format_bytes(_int_or_none(item.get('size')))}")
    types = payload.get("file_types")
    if isinstance(types, dict) and types:
        lines.extend(["", "File types:"])
        for name, count in types.items():
            lines.append(f"  {name}: {count}")
    warnings = payload.get("warnings") or []
    if isinstance(warnings, list) and warnings:
        lines.extend(["", "Warnings:"])
        for warning in warnings:
            warning = _as_dict(warning)
            text = f"  {warning['id']}: {warning['explanation']}"
            lines.append(paint(text, _YELLOW, colour))
    limitations = payload.get("limitations") or []
    if isinstance(limitations, list) and limitations:
        lines.extend(["", "Limitations:"])
        lines.extend(f"  {item}" for item in limitations)
    lines.append("")
    return "\n".join(lines)


def findings_text(payload: dict[str, object], *, colour: bool) -> str:
    """Render safety findings."""
    lines = [
        "Archive safety",
        "",
        "A safety scan does not detect malware and does not prove an archive is safe to extract.",
        "",
    ]
    findings = payload.get("findings") or []
    if not isinstance(findings, list) or not findings:
        lines.append("No findings.")
    else:
        for finding in findings:
            finding = _as_dict(finding)
            severity = str(finding["severity"])
            colour_code = _RED if severity in {"critical", "high"} else _YELLOW
            lines.append(paint(f"[{severity}] {finding['id']}", colour_code, colour))
            if finding.get("member"):
                lines.append(f"  Member: {escape_terminal(str(finding['member']))}")
            lines.append(f"  {finding['explanation']}")
            lines.append(f"  Consequence: {finding['consequence']}")
            lines.append(f"  Action: {finding['action']}")
            lines.append(f"  Limitation: {finding['limitations']}")
            lines.append("")
    return "\n".join(lines)


def tree_text(node: dict[str, object], *, sizes: bool) -> str:
    """Render a virtual tree."""
    lines: list[str] = []

    def walk(current: dict[str, object], prefix: str, last: bool, root: bool) -> None:
        name = escape_terminal(str(current["name"]))
        if current.get("nested_format"):
            name += f" [{current['nested_format']}]"
        if sizes and current.get("size") is not None:
            name += " " + format_bytes(_int_or_none(current.get("size")))
        if root:
            lines.append(name)
        else:
            branch = "└── " if last else "├── "
            lines.append(prefix + branch + name)
        children = current.get("children") or []
        children = _as_list(children)
        for index, child in enumerate(children):
            child = _as_dict(child)
            extension = "    " if last or root else "│   "
            walk(child, "" if root else prefix + extension, index == len(children) - 1, False)

    walk(node, "", True, True)
    return "\n".join(lines) + "\n"


def member_lines(members: list[dict[str, object]], *, long: bool) -> str:
    """Render list or find results."""
    if not long:
        return "".join(escape_terminal(str(member["virtual_path"])) + "\n" for member in members)
    lines = []
    for member in members:
        size = format_bytes(_int_or_none(member.get("size")))
        compressed = format_bytes(_int_or_none(member.get("compressed_size")))
        when = member.get("mtime") or "unavailable"
        mode = member.get("permissions")
        mode_text = "unavailable" if mode is None else format(_count(mode), "o")
        lines.append(
            f"{member['type']:<10} {size:>12} {compressed:>12} {when} {mode_text:>8} "
            f"{member.get('compression') or 'unavailable':<12} "
            f"{escape_terminal(str(member['virtual_path']))}"
        )
    return "\n".join(lines) + ("\n" if lines else "")


def diff_text(payload: dict[str, object]) -> str:
    """Render an archive comparison."""
    lines = ["Archive comparison", "", f"Mode: {payload.get('mode')}", ""]
    for label, key, prefix in (
        ("Added:", "added", "+"),
        ("Removed:", "removed", "-"),
        ("Modified:", "modified", "~"),
        ("Type changed:", "type_changed", "~"),
        ("Metadata changed:", "metadata_changed", "~"),
        ("Indeterminate:", "indeterminate", "?"),
    ):
        rows = payload.get(key) or []
        rows = _as_list(rows)
        if not rows:
            continue
        lines.append(label)
        for row in rows:
            row = _as_dict(row)
            lines.append(f"  {prefix} {escape_terminal(str(row.get('path')))}")
        lines.append("")
    lines.append(f"Unchanged: {format_count(_count(payload.get('unchanged', 0)))} members")
    note = payload.get("note")
    if note:
        lines.extend(["", str(note)])
    diffs = payload.get("text_diffs") or []
    if isinstance(diffs, list):
        for item in diffs:
            item = _as_dict(item)
            lines.extend(["", f"--- {item['path']}", str(item.get("diff") or "")])
    lines.append("")
    return "\n".join(lines)


def duplicates_text(payload: dict[str, object]) -> str:
    """Render duplicate groups."""
    groups = payload.get("groups") or []
    lines = ["Duplicate content", ""]
    if not isinstance(groups, list) or not groups:
        lines.append("No duplicate content.")
        return "\n".join(lines) + "\n"
    for index, group in enumerate(groups, start=1):
        group = _as_dict(group)
        lines.append(f"Group {index}")
        lines.append(f"  Hash: {group['hash']}")
        lines.append(f"  Size: {format_bytes(_int_or_none(group.get('size')))}")
        lines.append(f"  Occurrences: {group['occurrences']}")
        lines.append(
            "  Redundant uncompressed bytes: "
            + format_bytes(_int_or_none(group.get("redundant_uncompressed_bytes")))
        )
        savings = group.get("estimated_archive_savings")
        lines.append(
            "  Estimated archive storage savings: "
            + (format_bytes(_int_or_none(savings)) if savings is not None else "unavailable")
        )
        members = group.get("members") or []
        members = _as_list(members)
        for member in members:
            lines.append(f"  - {escape_terminal(str(member))}")
        lines.append("")
    return "\n".join(lines)


def test_text(payload: dict[str, object]) -> str:
    """Render an integrity report."""
    lines = [
        "Integrity test",
        "",
        f"Outcome: {payload.get('outcome')}",
        f"Tested: {payload.get('tested', 0)}",
        f"Passed: {payload.get('passed', 0)}",
        f"Failed: {payload.get('failed', 0)}",
        f"Skipped: {payload.get('skipped', 0)}",
        f"Unsupported: {payload.get('unsupported', 0)}",
        "",
        str(payload.get("verification") or ""),
    ]
    errors = payload.get("errors") or []
    if isinstance(errors, list) and errors:
        lines.extend(["", "Errors:"])
        for error in errors:
            error = _as_dict(error)
            lines.append(f"  {error.get('member')}: {error.get('message')}")
    limitations = payload.get("limitations") or []
    if isinstance(limitations, list) and limitations:
        lines.extend(["", "Limitations:"])
        lines.extend(f"  {item}" for item in limitations)
    lines.append("")
    return "\n".join(lines)


def formats_text(payload: dict[str, object]) -> str:
    """Render runtime format capabilities."""
    lines = ["Supported formats", ""]
    formats = payload.get("formats") or []
    formats = _as_list(formats)
    for item in formats:
        item = _as_dict(item)
        state = "available" if item["available"] else "unavailable"
        lines.append(f"{item['format']} ({state}, {item['backend']} {item['backend_version']})")
        flags = [
            "detection" if item["detection"] else None,
            "list" if item["listing"] else None,
            "stream" if item["streaming"] else None,
            "extract" if item["extraction"] else None,
            "integrity" if item["integrity"] else None,
            "encryption" if item["encryption"] else None,
            "nested" if item["nested"] else None,
            "random-access" if item["random_access"] else None,
        ]
        lines.append("  " + ", ".join(flag for flag in flags if flag))
        limitations = item.get("limitations") or []
        if isinstance(limitations, list):
            lines.extend(f"  - {limitation}" for limitation in limitations)
        lines.append("")
    return "\n".join(lines)


def report_markdown(payload: dict[str, object]) -> str:
    """Render a Markdown report from an inspect-style payload."""
    archive = payload["archive"]
    archive = _as_dict(archive)
    lines = [
        "# Archive Report",
        "",
        f"- Archive: `{archive['path']}`",
        f"- Format: `{archive['format']}`",
        f"- Compressed size: {archive['compressed_size']} bytes",
        f"- Declared uncompressed size: {archive['declared_uncompressed_size']} bytes",
        f"- Files: {archive['file_count']}",
        f"- Directories: {archive['directory_count']}",
        f"- Symlinks: {archive['symlink_count']}",
        f"- Backend: {archive['backend']} {archive['backend_version']}",
        "",
        "## Safety",
        "",
    ]
    findings = payload.get("warnings") or []
    if isinstance(findings, list) and findings:
        for finding in findings:
            finding = _as_dict(finding)
            lines.append(
                f"- **{finding['severity']}** `{finding['id']}`: "
                f"{escape_terminal(str(finding['explanation']))}"
            )
    else:
        lines.append("- No findings.")
    lines.extend(
        ["", "## Integrity", "", f"- Outcome: {payload.get('integrity_outcome', 'not run')}"]
    )
    lines.extend(["", "## Limitations", ""])
    limitations = payload.get("limitations") or []
    if isinstance(limitations, list) and limitations:
        lines.extend(f"- {item}" for item in limitations)
    else:
        lines.append("- None.")
    lines.append("")
    return "\n".join(lines)


def report_html(payload: dict[str, object]) -> str:
    """Render a self-contained offline HTML report."""
    archive = payload["archive"]
    archive = _as_dict(archive)
    rows = []
    for key in (
        "path",
        "format",
        "compressed_size",
        "declared_uncompressed_size",
        "file_count",
        "directory_count",
        "symlink_count",
        "backend",
    ):
        rows.append(
            "<tr><th>"
            + html.escape(key)
            + "</th><td>"
            + html.escape(str(archive.get(key)))
            + "</td></tr>"
        )
    finding_rows = []
    findings = payload.get("warnings") or []
    if isinstance(findings, list):
        for finding in findings:
            finding = _as_dict(finding)
            finding_rows.append(
                "<tr><td>"
                + html.escape(str(finding["severity"]))
                + "</td><td>"
                + html.escape(str(finding["id"]))
                + "</td><td>"
                + html.escape(str(finding["explanation"]))
                + "</td></tr>"
            )
    body = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Archive report</title>
<style>
body { font-family: sans-serif; margin: 2rem; }
table { border-collapse: collapse; width: 100%; margin: 1rem 0; }
th, td { border: 1px solid #ccc; padding: 0.4rem; text-align: left; vertical-align: top; }
</style>
</head>
<body>
<h1>Archive report</h1>
<p>This report is self-contained and does not contact a network.</p>
<table>
%s
</table>
<h2>Safety</h2>
<table>
<tr><th>Severity</th><th>Finding</th><th>Explanation</th></tr>
%s
</table>
<p>A safety scan does not detect malware and does not prove an archive is safe to extract.</p>
</body>
</html>
"""
    finding_html = "\n".join(finding_rows) or "<tr><td colspan='3'>No findings.</td></tr>"
    return body % ("\n".join(rows), finding_html)


def _as_dict(value: object) -> dict[str, object]:
    """Return a mapping or raise."""
    if isinstance(value, dict):
        return value
    raise TypeError("expected a mapping")


def _as_list(value: object) -> list[object]:
    """Return a list or raise."""
    if isinstance(value, list):
        return value
    raise TypeError("expected a list")


def _count(value: object) -> int:
    """Return an integer field, or zero when it is absent."""
    if isinstance(value, bool) or not isinstance(value, int):
        return 0
    return value


def _int_or_none(value: object) -> int | None:
    """Return an integer, or ``None`` when the field is absent."""
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value


def _float_or_none(value: object) -> float | None:
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, int | float):
        return float(value)
    return None


def _yes_no(value: object) -> str:
    if value is True:
        return "yes"
    if value is False:
        return "no"
    return "unknown"
