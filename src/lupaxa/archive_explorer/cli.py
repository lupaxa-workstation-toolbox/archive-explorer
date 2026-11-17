"""Command-line interface for Archive Explorer."""

from __future__ import annotations

import argparse
import getpass
import os
import sys
from collections.abc import Sequence
from datetime import datetime
from pathlib import Path
from typing import Any, BinaryIO, Never, TextIO

from lupaxa.archive_explorer.archive import make_workspace
from lupaxa.archive_explorer.commands import (
    release,
    run_cat,
    run_diff,
    run_duplicates,
    run_find,
    run_formats,
    run_get,
    run_grep,
    run_inspect,
    run_list,
    run_nested,
    run_report,
    run_safety,
    run_test,
    run_tree,
    run_version,
)
from lupaxa.archive_explorer.config import Settings, load_settings
from lupaxa.archive_explorer.context import Context
from lupaxa.archive_explorer.errors import AppError, ExitCode, redact
from lupaxa.archive_explorer.limits import Budget
from lupaxa.archive_explorer.version import get_version

_REPORT_FORMATS = ("text", "json", "jsonl", "markdown", "html")
_MACHINE_FORMATS = ("text", "json", "jsonl")


class Parser(argparse.ArgumentParser):
    """Argument parser that writes help to an injected stream."""

    def __init__(self, *args: Any, output: TextIO | None = None, **kwargs: Any) -> None:  # noqa: ANN401
        super().__init__(*args, **kwargs)
        self._output = output if output is not None else sys.stderr

    def add_subparsers(self, **kwargs: Any) -> Any:  # noqa: ANN401
        """Give every subcommand the same output stream."""
        output = self._output

        class _Bound(Parser):
            def __init__(self, *args: Any, **inner: Any) -> None:  # noqa: ANN401
                super().__init__(*args, output=output, **inner)

        kwargs.setdefault("parser_class", _Bound)
        return super().add_subparsers(**kwargs)

    def _print_message(self, message: str, file: Any = None) -> None:  # noqa: ANN401
        if message:
            target: TextIO = file if file is not None else self._output
            target.write(message)

    def print_help(self, file: Any = None) -> None:  # noqa: ANN401
        """Write help to the injected stream."""
        super().print_help(file or self._output)

    def exit(self, status: int = 0, message: str | None = None) -> Never:
        """Raise instead of terminating the interpreter."""
        if message:
            self._output.write(message)
        raise SystemExit(status)


def _size(value: str) -> int:
    text = value.strip().lower()
    units = {
        "b": 1,
        "k": 1000,
        "kb": 1000,
        "kib": 1024,
        "m": 1000**2,
        "mb": 1000**2,
        "mib": 1024**2,
        "g": 1000**3,
        "gb": 1000**3,
        "gib": 1024**3,
    }
    number = text
    suffix = "b"
    for name in sorted(units, key=len, reverse=True):
        if text.endswith(name) and (name != "b" or text[:-1].isdigit()):
            number = text[: -len(name)] or "0"
            suffix = name
            break
    try:
        amount = int(number)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("size must be an integer with an optional unit") from exc
    if amount < 0:
        raise argparse.ArgumentTypeError("size must be 0 or greater")
    return amount * units[suffix]


def _date(value: str) -> datetime:
    try:
        return datetime.strptime(value, "%Y-%m-%d")
    except ValueError as exc:
        raise argparse.ArgumentTypeError("date must be YYYY-MM-DD") from exc


def build_parser(output: TextIO) -> Parser:
    """Build the archive-explorer parser."""
    parser = Parser(
        prog="archive-explorer",
        description="Inspect, search, and read archives without extracting them completely.",
        output=output,
    )
    parser.add_argument("--version", action="version", version=f"archive-explorer {get_version()}")
    common = _common(output)
    walk = _walk(output)
    sub = parser.add_subparsers(dest="command", required=True)
    _add_archive_commands(sub, common, walk)
    sub.add_parser("formats", parents=[common], help="show supported formats")
    sub.add_parser("version", help="show version information")
    return parser


def _member_ceiling(parser: Parser) -> None:
    """Limit one decompressed member. On find, --max-size is the search filter."""
    parser.add_argument("--max-size", dest="max_size", type=_size)


def _common(output: TextIO) -> Parser:
    common = Parser(add_help=False, output=output)
    common.add_argument("--verbose", action="store_true")
    common.add_argument("--quiet", action="store_true")
    common.add_argument("--no-colour", action="store_true")
    common.add_argument("--config", type=Path)
    common.add_argument("--timeout", type=float)
    common.add_argument("--password-file", type=Path)
    common.add_argument("--password-stdin", action="store_true")
    common.add_argument("--force", action="store_true")
    common.add_argument("--archive-format")
    common.add_argument("--max-depth", type=int)
    common.add_argument("--max-member-size", dest="max_size", type=_size)
    common.add_argument("--json", action="store_true")
    common.add_argument("--jsonl", action="store_true")
    common.add_argument("--output", dest="output_path", type=Path)
    return common


def _walk(output: TextIO) -> Parser:
    walk = Parser(add_help=False, output=output)
    walk.add_argument("--nested", action="store_true")
    walk.add_argument("--recursive", action="store_true")
    return walk


def _add_archive_commands(
    sub: argparse._SubParsersAction[Parser], common: Parser, walk: Parser
) -> None:
    inspect = sub.add_parser("inspect", parents=[common, walk], help="analyse an archive")
    _member_ceiling(inspect)
    inspect.add_argument("archive", type=Path)
    inspect.add_argument("--detailed", action="store_true")
    inspect.add_argument("--member")
    listing = sub.add_parser("list", parents=[common], help="list archive members")
    _member_ceiling(listing)
    listing.add_argument("archive", type=Path)
    listing.add_argument("--path")
    listing.add_argument("--sort", choices=("name", "size", "date", "type", "ratio"))
    listing.add_argument("--descending", action="store_true")
    listing.add_argument("--long", dest="long_format", action="store_true")
    listing.add_argument(
        "--type", dest="entry_type", choices=("file", "directory", "symlink", "hardlink", "other")
    )
    listing.add_argument("--limit", type=int)
    listing.add_argument("--offset", type=int)
    tree = sub.add_parser("tree", parents=[common], help="show a virtual directory tree")
    _member_ceiling(tree)
    tree.add_argument("archive", type=Path)
    tree.add_argument("--depth", type=int)
    tree.add_argument("--sizes", action="store_true")
    tree.add_argument("--path")
    tree.add_argument("--directories-only", action="store_true")
    find = sub.add_parser("find", parents=[common, walk], help="search members")
    find.add_argument("archive", type=Path)
    find.add_argument("pattern", nargs="?")
    find.add_argument("--regex", action="store_true")
    find.add_argument("--ignore-case", action="store_true")
    find.add_argument("--full-path", action="store_true")
    find.add_argument(
        "--type", dest="entry_type", choices=("file", "directory", "symlink", "hardlink", "other")
    )
    find.add_argument("--min-size", type=_size)
    find.add_argument("--max-size", dest="max_size_filter", type=_size)
    find.add_argument("--modified-after", type=_date)
    find.add_argument("--modified-before", type=_date)
    find.add_argument("--compression")
    find.add_argument("--encrypted", action="store_true")
    find.add_argument("--not-encrypted", action="store_true")
    find.add_argument("--match", choices=("all", "any"), default="all")
    find.add_argument("--fail-on-empty", action="store_true")
    grep = sub.add_parser("grep", parents=[common, walk], help="search text inside members")
    _member_ceiling(grep)
    grep.add_argument("archive", type=Path)
    grep.add_argument("pattern")
    grep.add_argument("--regex", action="store_true")
    grep.add_argument("--ignore-case", action="store_true")
    grep.add_argument("--include")
    grep.add_argument("--exclude")
    grep.add_argument("--encoding")
    grep.add_argument("--encoding-errors", choices=("strict", "replace", "ignore"))
    grep.add_argument("--context", type=int)
    grep.add_argument("--count", action="store_true")
    grep.add_argument("--files-with-matches", action="store_true")
    grep.add_argument("--binary", action="store_true")
    grep.add_argument("--fail-on-empty", action="store_true")
    cat = sub.add_parser("cat", parents=[common], help="stream a member to stdout")
    _member_ceiling(cat)
    cat.add_argument("archive", type=Path)
    cat.add_argument("--path")
    cat.add_argument("--index", type=int)
    cat.add_argument("--selector")
    cat.add_argument("--follow-symlinks", action="store_true")
    get = sub.add_parser("get", parents=[common], help="extract selected members")
    _member_ceiling(get)
    get.add_argument("archive", type=Path)
    get.add_argument("--path", dest="paths", action="append")
    get.add_argument("--glob", dest="globs", action="append")
    get.add_argument("--index", type=int)
    get.add_argument("--dest", type=Path)
    get.add_argument("--flatten", action="store_true")
    get.add_argument("--dry-run", action="store_true")
    get.add_argument("--allow-symlinks", action="store_true")
    get.add_argument("--allow-hardlinks", action="store_true")
    diff = sub.add_parser("diff", parents=[common, walk], help="compare two archives")
    _member_ceiling(diff)
    diff.add_argument("old", type=Path)
    diff.add_argument("new", type=Path)
    diff.add_argument("--mode", choices=("fast", "content", "detailed"), default="fast")
    diff.add_argument("--ignore-case-paths", action="store_true")
    diff.add_argument("--ignore-whitespace", action="store_true")
    diff.add_argument("--context", type=int)
    duplicates = sub.add_parser(
        "duplicates", parents=[common, walk], help="find duplicate contents"
    )
    _member_ceiling(duplicates)
    duplicates.add_argument("archives", type=Path, nargs="+")
    duplicates.add_argument("--hash", dest="hash_algorithm", default="sha256")
    nested = sub.add_parser("nested", parents=[common], help="discover nested archives")
    _member_ceiling(nested)
    nested.add_argument("archive", type=Path)
    nested.add_argument("--depth", type=int)
    safety = sub.add_parser("safety", parents=[common, walk], help="assess extraction risks")
    _member_ceiling(safety)
    safety.add_argument("archive", type=Path)
    test = sub.add_parser("test", parents=[common, walk], help="test archive integrity")
    _member_ceiling(test)
    test.add_argument("archive", type=Path)
    test.add_argument("--full", action="store_true")
    report = sub.add_parser("report", parents=[common, walk], help="write a report")
    _member_ceiling(report)
    report.add_argument("archive", type=Path)
    report.add_argument("--format", dest="report_format", choices=_REPORT_FORMATS)
    report.add_argument("--full", action="store_true")


def main(
    argv: Sequence[str] | None = None,
    *,
    stdout: BinaryIO | None = None,
    stderr: TextIO | None = None,
    stdin: TextIO | None = None,
    environ: dict[str, str] | None = None,
    home: Path | None = None,
) -> int:
    """Run Archive Explorer and return an exit code."""
    out = stdout if stdout is not None else sys.stdout.buffer
    err = stderr if stderr is not None else sys.stderr
    inn = stdin if stdin is not None else sys.stdin
    env = dict(os.environ if environ is None else environ)
    parser = build_parser(err)
    try:
        args = parser.parse_args(list(argv) if argv is not None else None)
    except SystemExit as exc:
        code = exc.code
        return int(code) if isinstance(code, int) else ExitCode.USAGE
    try:
        return _run(args, out, err, inn, env, home)
    except AppError as exc:
        err.write(redact(exc.message, []) + "\n")
        return exc.code
    except BrokenPipeError:
        return ExitCode.OK
    except OSError as exc:
        err.write(f"{exc}\n")
        return ExitCode.FAILURE


def _run(
    args: argparse.Namespace,
    out: BinaryIO,
    err: TextIO,
    inn: TextIO,
    env: dict[str, str],
    home: Path | None,
) -> int:
    if getattr(args, "verbose", False) and getattr(args, "quiet", False):
        raise AppError("--verbose and --quiet cannot be combined", ExitCode.USAGE)
    if getattr(args, "json", False) and getattr(args, "jsonl", False):
        raise AppError("--json and --jsonl cannot be combined", ExitCode.USAGE)
    settings = load_settings(env, home, getattr(args, "config", None))
    _apply_limits(settings, args)
    password = _password(args, settings, inn, env)
    budget = Budget(settings.resolved_limits())
    workspace = make_workspace(settings.temp_directory, budget)
    ctx = Context(
        stdout=out,
        stderr=err,
        settings=settings,
        budget=budget,
        workspace=workspace,
        password=password,
        colour=_colour(args, settings, out, env),
        verbose=bool(getattr(args, "verbose", False)),
        quiet=bool(getattr(args, "quiet", False)),
        force=bool(getattr(args, "force", False)),
        archive_format=getattr(args, "archive_format", None),
        output_format=_output_format(args, settings),
        output_path=getattr(args, "output_path", None),
        follow_symlinks=bool(getattr(args, "follow_symlinks", False) or settings.follow_symlinks),
        secrets=[password] if password else [],
    )
    if getattr(args, "recursive", False):
        args.nested = True
    try:
        try:
            return _dispatch(ctx, args)
        except AppError as exc:
            if (
                exc.code == ExitCode.PASSWORD
                and password is None
                and err.isatty()
                and "password" in exc.message
            ):
                prompted = getpass.getpass("Password: ", stream=err)
                ctx.password = prompted
                ctx.secrets.append(prompted)
                return _dispatch(ctx, args)
            raise
    finally:
        release(ctx)


def _dispatch(ctx: Context, args: argparse.Namespace) -> int:
    command = str(args.command)
    if command == "inspect":
        return run_inspect(
            ctx,
            args.archive,
            detailed=bool(args.detailed),
            member=args.member,
            nested=bool(args.nested),
        )
    if command == "list":
        return run_list(ctx, args.archive, args)
    if command == "tree":
        return run_tree(ctx, args.archive, args)
    if command == "find":
        return run_find(ctx, args.archive, args)
    if command == "grep":
        return run_grep(ctx, args.archive, args)
    if command == "cat":
        return run_cat(ctx, args.archive, args)
    if command == "get":
        if ctx.output_path is not None and getattr(args, "output_file", None) is None:
            args.output_file = ctx.output_path
            ctx.output_path = None
        return run_get(ctx, args.archive, args)
    if command == "diff":
        return run_diff(ctx, args.old, args.new, args)
    if command == "duplicates":
        return run_duplicates(ctx, args.archives, args)
    if command == "nested":
        return run_nested(ctx, args.archive, args.depth)
    if command == "safety":
        return run_safety(ctx, args.archive, nested=bool(args.nested))
    if command == "test":
        return run_test(ctx, args.archive, full=bool(args.full), nested=bool(args.nested))
    if command == "report":
        if getattr(args, "report_format", None):
            ctx.output_format = str(args.report_format)
        return run_report(ctx, args.archive, full=bool(args.full), nested=bool(args.nested))
    if command == "formats":
        return run_formats(ctx)
    if command == "version":
        return run_version(ctx, get_version())
    raise AppError(f"unknown command {command}", ExitCode.USAGE)


def _apply_limits(settings: Settings, args: argparse.Namespace) -> None:
    limits = settings.resolved_limits()
    max_depth = getattr(args, "max_depth", None)
    if max_depth is not None:
        if max_depth < 0:
            raise AppError("--max-depth must be 0 or greater", ExitCode.USAGE)
        limits.max_depth = max_depth
    max_size = getattr(args, "max_size", None)
    if max_size is not None:
        limits.max_member_bytes = max_size
    timeout = getattr(args, "timeout", None)
    if timeout is not None:
        if timeout <= 0:
            raise AppError("--timeout must be greater than 0", ExitCode.USAGE)
        limits.max_seconds = float(timeout)
    settings.limits = limits


def _password(
    args: argparse.Namespace, settings: Settings, stdin: TextIO, environ: dict[str, str]
) -> str | None:
    password_file = getattr(args, "password_file", None)
    password_stdin = bool(getattr(args, "password_stdin", False))
    if password_file and password_stdin:
        raise AppError("use only one of --password-file and --password-stdin", ExitCode.USAGE)
    if password_file:
        text = Path(password_file).read_text(encoding="utf-8")
        if text.endswith("\n"):
            text = text[:-1]
        if text.endswith("\r"):
            text = text[:-1]
        return text
    if password_stdin:
        line = stdin.readline()
        return line[:-1] if line.endswith("\n") else line
    if settings.allow_password_env:
        return environ.get("ARCHIVE_EXPLORER_PASSWORD") or None
    return None


def _colour(
    args: argparse.Namespace, settings: Settings, stdout: BinaryIO, environ: dict[str, str]
) -> bool:
    if getattr(args, "no_colour", False) or environ.get("NO_COLOR") or not settings.colour:
        return False
    if environ.get("FORCE_COLOR"):
        return True
    return bool(getattr(stdout, "isatty", lambda: False)())


def _output_format(args: argparse.Namespace, settings: Settings) -> str:
    if args.command == "cat":
        return "text"
    if getattr(args, "json", False):
        return "json"
    if getattr(args, "jsonl", False):
        return "jsonl"
    report_format = getattr(args, "report_format", None)
    if args.command == "report" and report_format:
        return str(report_format)
    chosen = settings.report_format if args.command == "report" else settings.output_format
    allowed = _REPORT_FORMATS if args.command == "report" else _MACHINE_FORMATS
    return chosen if chosen in allowed else "text"
