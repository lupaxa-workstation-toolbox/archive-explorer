"""Metadata safety checks for untrusted archives.

A completed scan is not a malware verdict. It reports extraction hazards
and resource indicators only.
"""

from __future__ import annotations

import unicodedata
from collections import defaultdict

from lupaxa.archive_explorer.limits import Limits
from lupaxa.archive_explorer.models import Finding, Member
from lupaxa.archive_explorer.paths import (
    has_invalid_characters,
    has_traversal,
    is_absolute_member,
    is_reserved_name,
    is_unc,
    is_windows_drive,
    path_parts,
)

_SEVERITY = ("critical", "high", "medium", "low", "informational", "unknown")


def analyse(
    members: list[Member],
    *,
    compressed_size: int | None,
    limits: Limits,
    nested_depth: int = 1,
    malformed: str | None = None,
) -> list[Finding]:
    """Return findings for member metadata and declared sizes."""
    findings: list[Finding] = []
    if malformed:
        findings.append(
            _finding(
                "structure.malformed",
                None,
                "critical",
                malformed,
                "The archive may be truncated, hostile, or not the format it resembles.",
                "Do not extract it. Obtain another copy if the file should be valid.",
                "Detection uses the accessible header and structure only.",
            )
        )
    seen: dict[str, list[Member]] = defaultdict(list)
    folded: dict[str, list[Member]] = defaultdict(list)
    normalised: dict[str, list[Member]] = defaultdict(list)
    declared = 0
    declared_complete = True
    for member in members:
        seen[member.path].append(member)
        folded[member.path.casefold()].append(member)
        key = unicodedata.normalize("NFC", member.normalised_path or member.path)
        normalised[key].append(member)
        if member.member_type == "file":
            if member.size is None:
                declared_complete = False
            else:
                declared += member.size
        _member_findings(member, limits, findings)
    for path, group in seen.items():
        if len(group) > 1:
            findings.append(
                _finding(
                    "path.duplicate",
                    path,
                    "medium",
                    f"{len(group)} members share the path {path}.",
                    "Tools that keep only one entry can hide or replace content.",
                    "Select a member by index or occurrence. Do not assume the first entry wins.",
                    "The count is based on the original member path.",
                )
            )
    for key, group in folded.items():
        originals = {item.path for item in group}
        if len(originals) > 1:
            findings.append(
                _finding(
                    "path.case-collision",
                    key,
                    "medium",
                    "These paths collide when compared without case: "
                    + ", ".join(sorted(originals)),
                    "A case-insensitive filesystem can overwrite one file with another.",
                    "Extract with flattened, unique names or onto a case-sensitive filesystem.",
                    "The check uses Unicode case folding.",
                )
            )
    for key, group in normalised.items():
        originals = {item.path for item in group}
        if len(originals) > 1:
            findings.append(
                _finding(
                    "path.unicode-collision",
                    key,
                    "medium",
                    "These paths collide under Unicode NFC: " + ", ".join(sorted(originals)),
                    "A normalising filesystem can treat them as one name.",
                    "Extract with distinct destination names.",
                    "The check uses NFC only.",
                )
            )
    if limits.max_decompressed_bytes and declared > limits.max_decompressed_bytes:
        findings.append(
            _finding(
                "bomb.declared",
                None,
                "high",
                f"Declared uncompressed size is {declared} bytes.",
                "Decompressing the archive can exhaust disk or memory.",
                "Raise the limit only when the source is trusted, or inspect members individually.",
                "Declared sizes can be smaller or larger than the real stream.",
            )
        )
    if (
        compressed_size
        and declared_complete
        and compressed_size > 0
        and declared / compressed_size >= limits.suspicious_ratio
        and declared >= 1_000_000
    ):
        findings.append(
            _finding(
                "compression.suspicious-ratio",
                None,
                "high",
                f"Declared expansion is {declared / compressed_size:.0f}:1.",
                "A small download can expand into a very large file.",
                "Test with a decompressed-byte limit before a full extract.",
                "The ratio uses declared sizes and is not a proof of a bomb.",
            )
        )
    if limits.max_depth and nested_depth > limits.max_depth:
        findings.append(
            _finding(
                "bomb.nested",
                None,
                "high",
                f"Nested archive depth {nested_depth} exceeds the limit of {limits.max_depth}.",
                "Repeated nesting can multiply work and temporary storage.",
                "Stop at the configured depth.",
                "Depth counts archive containers, including the outermost file.",
            )
        )
    findings.sort(
        key=lambda item: (_SEVERITY.index(item.severity), item.finding_id, item.member or "")
    )
    return findings


def _member_findings(member: Member, limits: Limits, findings: list[Finding]) -> None:
    path = member.path
    if is_absolute_member(path):
        findings.append(
            _finding(
                "path.absolute",
                path,
                "high",
                "The member path is absolute.",
                "A naive extract can write outside the destination directory.",
                "Keep extraction confined to the chosen directory.",
                "Absolute paths are recognised for POSIX, drive-letter, and UNC forms.",
            )
        )
    if is_windows_drive(path):
        findings.append(
            _finding(
                "path.windows-drive",
                path,
                "high",
                "The member path includes a Windows drive.",
                "Extracting on Windows can target another volume.",
                "Reject the member or rewrite the destination name.",
                "The drive letter is taken from the member name, not from this computer.",
            )
        )
    if is_unc(path):
        findings.append(
            _finding(
                "path.unc",
                path,
                "high",
                "The member path is a UNC path.",
                "Extracting it can address a network share.",
                "Reject the member.",
                "UNC detection treats both slash styles as equivalent.",
            )
        )
    if has_traversal(path):
        findings.append(
            _finding(
                "path.traversal",
                path,
                "critical",
                "The member path contains a parent-directory segment.",
                "Extraction can escape the destination directory.",
                "Reject the member.",
                "The check looks at path components after slash normalisation.",
            )
        )
    if member.member_type == "symlink":
        findings.append(
            _finding(
                "link.symlink",
                path,
                "medium",
                "The member is a symbolic link"
                + (f" to {member.link_target}." if member.link_target else "."),
                "A link can point at a file outside the destination after extraction.",
                "Do not create the link unless that target has been checked.",
                "Links are not followed during virtual file access.",
            )
        )
        if member.link_target and (
            is_absolute_member(member.link_target) or has_traversal(member.link_target)
        ):
            findings.append(
                _finding(
                    "link.escapes",
                    path,
                    "critical",
                    f"The link target {member.link_target} leaves an extraction root.",
                    "Following the link can read or write outside the destination.",
                    "Do not create or follow the link.",
                    "The target is the value stored in the archive.",
                )
            )
    if member.member_type == "hardlink":
        findings.append(
            _finding(
                "link.hardlink",
                path,
                "medium",
                "The member is a hard link"
                + (f" to {member.link_target}." if member.link_target else "."),
                "A hard link can alias a file outside the destination.",
                "Create a regular copy, or allow the link only after the target is confined.",
                "Not every format records a resolvable target.",
            )
        )
    if member.member_type == "other":
        findings.append(
            _finding(
                "entry.special",
                path,
                "high",
                "The member is a special filesystem entry.",
                "Creating it can expose a device, fifo, or other non-regular file.",
                "Skip the member. Archive Explorer does not create device nodes.",
                "The member type comes from the archive metadata.",
            )
        )
    for part in path_parts(path):
        if is_reserved_name(part):
            findings.append(
                _finding(
                    "path.reserved-windows",
                    path,
                    "medium",
                    f"The component {part} is reserved on Windows.",
                    "Extraction on Windows can fail or address a device.",
                    "Rename the member before extracting it on Windows.",
                    "The check also runs on other operating systems.",
                )
            )
            break
    if has_invalid_characters(path):
        findings.append(
            _finding(
                "path.invalid-characters",
                path,
                "medium",
                "The member path contains characters that are problematic on Windows.",
                "Extraction can fail or produce a surprising name.",
                "Rename the member before extracting it.",
                "Controls, quotes, wildcards, trailing dots, and trailing spaces are included.",
            )
        )
    parts = path_parts(path)
    if len(path) > 260 or any(len(part) > 255 for part in parts):
        findings.append(
            _finding(
                "path.too-long",
                path,
                "low",
                "The member path is longer than common filesystem limits.",
                "Extraction can fail on Windows or on filesystems with short name limits.",
                "Extract with a shorter destination name.",
                "The thresholds are 260 characters for the path and 255 for a component.",
            )
        )
    if len(parts) > limits.max_path_components:
        findings.append(
            _finding(
                "path.deep-nesting",
                path,
                "low",
                f"The member path has {len(parts)} components.",
                "Deep trees are hard to inspect and can stress path limits.",
                "Extract a smaller subtree or flatten the names.",
                f"The configured component limit is {limits.max_path_components}.",
            )
        )
    if (
        member.size is not None
        and member.compressed_size is not None
        and member.compressed_size >= 0
        and member.size >= 1_000_000
        and member.size / max(member.compressed_size, 1) >= limits.suspicious_ratio
    ):
        findings.append(
            _finding(
                "compression.suspicious-ratio",
                path,
                "medium",
                "The member declares a very large expansion relative to its compressed size.",
                "Decompressing this member can use much more space than the archive.",
                "Read it under the decompressed-byte limit.",
                "Per-member compressed sizes are unavailable for some formats.",
            )
        )
    if (
        member.size is not None
        and limits.max_member_bytes
        and member.size > limits.max_member_bytes
    ):
        findings.append(
            _finding(
                "compression.excessive-size",
                path,
                "high",
                f"The member declares {member.size} uncompressed bytes.",
                "Reading it exceeds the configured single-member limit.",
                "Raise the limit only for a trusted archive.",
                "The declared size may not match the stream.",
            )
        )
    if member.encrypted:
        findings.append(
            _finding(
                "encryption.present",
                path,
                "informational",
                "The member is encrypted.",
                "Contents, tests, and extraction need a password and a supported method.",
                "Supply a password by a prompt, file, or standard input. "
                "Do not put it on the command line.",
                "Metadata may still be visible without the password.",
            )
        )
    if member.compression and (
        member.compression.startswith("unsupported") or member.compression.startswith("method-")
    ):
        findings.append(
            _finding(
                "compression.unsupported",
                path,
                "medium",
                f"Compression method {member.compression} is not supported.",
                "The member cannot be streamed or tested.",
                "Use a tool that implements this method, or skip the member.",
                "Support depends on the active backend.",
            )
        )


def _finding(
    finding_id: str,
    member: str | None,
    severity: str,
    explanation: str,
    consequence: str,
    action: str,
    limitations: str,
) -> Finding:
    return Finding(finding_id, member, severity, explanation, consequence, action, limitations)
