"""Virtual member selectors.

The display form ``projects/source.tar.gz::config/settings.toml`` splits on
``::``. A segment ``#12`` selects the 1-based member index. A segment ending
in ``@@N`` (digits only) selects that occurrence of a duplicated path.

Names that themselves contain ``::`` or a trailing ``@@N`` need ``--selector``,
a JSON list of objects with ``path``, ``index``, and ``occurrence``.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

from lupaxa.archive_explorer.errors import AppError, ExitCode


@dataclass
class Segment:
    """One step in a nested member address."""

    path: str | None = None
    index: int | None = None
    occurrence: int | None = None


def parse_virtual_path(text: str) -> list[Segment]:
    """Parse a ``::`` virtual path."""
    if text == "":
        raise AppError("member path is empty", ExitCode.USAGE)
    segments: list[Segment] = []
    for part in text.split("::"):
        if part.startswith("#") and part[1:].isdigit() and int(part[1:]) > 0:
            segments.append(Segment(index=int(part[1:])))
            continue
        path = part
        occurrence: int | None = None
        if "@@" in part:
            stem, suffix = part.rsplit("@@", 1)
            if suffix.isdigit() and int(suffix) > 0 and stem != "":
                path = stem
                occurrence = int(suffix)
        if path == "":
            raise AppError("member path contains an empty segment", ExitCode.USAGE)
        segments.append(Segment(path=path, occurrence=occurrence))
    return segments


def parse_selector_json(text: str) -> list[Segment]:
    """Parse a JSON selector object or list."""
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise AppError(f"selector is not valid JSON: {exc}", ExitCode.USAGE) from exc
    if isinstance(data, dict):
        items = [data]
    elif isinstance(data, list):
        items = data
    else:
        raise AppError("selector must be an object or a list of objects", ExitCode.USAGE)
    segments: list[Segment] = []
    for item in items:
        if not isinstance(item, dict):
            raise AppError("each selector entry must be an object", ExitCode.USAGE)
        path = item.get("path")
        index = item.get("index")
        occurrence = item.get("occurrence")
        if path is not None and not isinstance(path, str):
            raise AppError("selector path must be a string", ExitCode.USAGE)
        if index is not None and (isinstance(index, bool) or not isinstance(index, int)):
            raise AppError("selector index must be an integer", ExitCode.USAGE)
        if occurrence is not None and (
            isinstance(occurrence, bool) or not isinstance(occurrence, int)
        ):
            raise AppError("selector occurrence must be an integer", ExitCode.USAGE)
        if (path is None) == (index is None):
            raise AppError("selector entry needs exactly one of path or index", ExitCode.USAGE)
        if index is not None and index < 1:
            raise AppError("selector index starts at 1", ExitCode.USAGE)
        if occurrence is not None and occurrence < 1:
            raise AppError("selector occurrence starts at 1", ExitCode.USAGE)
        segments.append(
            Segment(
                path=path,
                index=index,
                occurrence=occurrence,
            )
        )
    if not segments:
        raise AppError("selector is empty", ExitCode.USAGE)
    return segments
