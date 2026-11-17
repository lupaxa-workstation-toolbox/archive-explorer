"""Archive backends.

Each backend lists members from metadata and opens one member at a time.
A backend does not advertise a capability it cannot perform.
"""

from __future__ import annotations

import bz2
import gzip
import io
import lzma
import sys
import tarfile
import zipfile
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import IO, BinaryIO, Literal, cast

from lupaxa.archive_explorer.errors import AppError, ExitCode
from lupaxa.archive_explorer.limits import Budget
from lupaxa.archive_explorer.models import Capability, Member
from lupaxa.archive_explorer.paths import normalise_path

_ZIP_METHODS = {
    0: "store",
    8: "deflate",
    9: "deflate64",
    12: "bzip2",
    14: "lzma",
    93: "zstd",
    95: "xz",
}


class CountingReader:
    """Read a member in bounded chunks and charge the shared budget."""

    def __init__(self, raw: IO[bytes], budget: Budget, stop_at: int | None = None) -> None:
        self._raw = raw
        self._budget = budget
        self._stop_at = stop_at
        self.total = 0
        self._closed = False

    def read(self, size: int = -1) -> bytes:
        """Return the next chunk, or ``b''`` at the end."""
        if self._closed:
            return b""
        if self._stop_at is not None and self.total >= self._stop_at:
            return b""
        request = 1024 * 1024 if size is None or size < 0 else size
        request = min(request, 1024 * 1024)
        if self._stop_at is not None:
            request = min(request, self._stop_at - self.total)
        remaining_member = self._budget.limits.max_member_bytes
        if remaining_member:
            request = min(request, max(remaining_member - self.total, 0))
        remaining_total = self._budget.limits.max_decompressed_bytes
        if remaining_total:
            request = min(request, max(remaining_total - self._budget.decompressed, 0))
        if request <= 0:
            self._budget.account_read(0, self.total + 1)
            return b""
        data = self._raw.read(request)
        if not data:
            return b""
        self.total += len(data)
        self._budget.account_read(len(data), self.total)
        return data

    def close(self) -> None:
        """Close the underlying stream."""
        if not self._closed:
            self._raw.close()
            self._closed = True

    def __enter__(self) -> CountingReader:
        """Return this reader."""
        return self

    def __exit__(self, *_exc: object) -> None:
        """Close this reader."""
        self.close()


class ArchiveSession:
    """An open archive."""

    format_id = ""
    backend_name = ""
    backend_version = ""
    random_access = False

    def __init__(self, path: Path, display_path: str, password: str | None) -> None:
        self.path = path
        self.display_path = display_path
        self._password = password
        self.limitations: list[str] = []
        self.comment: str | None = None
        self.compression: str | None = None
        self.materialised = False
        self._members: list[Member] | None = None

    def list_members(self) -> list[Member]:
        """Return members in archive order."""
        if self._members is None:
            self._members = self._load_members()
        return self._members

    def open_member(
        self, member: Member, budget: Budget, stop_at: int | None = None
    ) -> CountingReader:
        """Stream one regular file."""
        raise AppError("this backend cannot stream members", ExitCode.UNSUPPORTED)

    def test_member(self, member: Member, budget: Budget) -> str:
        """Return passed, failed, skipped, or unsupported for one member."""
        if member.member_type != "file":
            return "skipped"
        if member.encrypted and not self._password:
            return "skipped"
        try:
            with self.open_member(member, budget) as reader:
                while reader.read():
                    pass
        except AppError as exc:
            if exc.code == ExitCode.UNSUPPORTED:
                return "unsupported"
            return "failed"
        return "passed"

    def close(self) -> None:
        """Release archive handles."""

    def _load_members(self) -> list[Member]:
        raise AppError("this backend cannot list members", ExitCode.UNSUPPORTED)

    def __repr__(self) -> str:
        """Return a debug representation."""
        return f"ArchiveSession({self.format_id}, {self.display_path})"


def _stamp(members: list[Member], display_path: str) -> list[Member]:
    counts: dict[str, int] = {}
    for member in members:
        counts[member.path] = counts.get(member.path, 0) + 1
        member.occurrence = counts[member.path]
        member.member_id = f"member-{member.index:06d}"
        member.archive_path = display_path
        member.normalised_path = normalise_path(member.path)
    return members


class ZipSession(ArchiveSession):
    """ZIP via the Python standard library."""

    format_id = "zip"
    backend_name = "zipfile"
    backend_version = getattr(zipfile, "__version__", f"python-{sys.version.split()[0]}")
    random_access = True

    def __init__(self, path: Path, display_path: str, password: str | None) -> None:
        super().__init__(path, display_path, password)
        self.limitations.append(
            "Traditional ZipCrypto can be decrypted. AES-encrypted ZIP members are not supported. "
            "ZipCrypto is not strong encryption."
        )
        try:
            self._zip = zipfile.ZipFile(path, mode="r")
        except zipfile.BadZipFile as exc:
            raise AppError(f"zip archive is corrupt or truncated: {exc}", ExitCode.CORRUPT) from exc
        comment = self._zip.comment.decode("utf-8", errors="replace") if self._zip.comment else ""
        self.comment = comment or None

    def close(self) -> None:
        """Close the zip handle."""
        self._zip.close()

    def _load_members(self) -> list[Member]:
        members: list[Member] = []
        for index, info in enumerate(self._zip.infolist(), start=1):
            encrypted = bool(info.flag_bits & 0x1)
            method = _ZIP_METHODS.get(info.compress_type)
            if method is None:
                method = f"unsupported-{info.compress_type}"
            if info.compress_type == 99:
                method = "unsupported-aes"
            member_type = "directory" if info.is_dir() else "file"
            permissions = None
            if info.create_system == 3:
                permissions = (info.external_attr >> 16) & 0xFFFF
                if permissions & 0o170000 == 0o120000 and not info.is_dir():
                    member_type = "symlink"
            encoding = "utf-8" if info.flag_bits & 0x800 else None
            mtime = None
            if info.date_time and info.date_time[0] > 1980:
                try:
                    mtime = datetime(*info.date_time)
                except ValueError:
                    mtime = None
            link_target = None
            if member_type == "symlink" and not encrypted and info.file_size <= 4096:
                link_target = self._read_link(info)
            members.append(
                Member(
                    index=index,
                    path=info.filename,
                    normalised_path=info.filename.replace("\\", "/"),
                    member_type=member_type,
                    size=0 if info.is_dir() else info.file_size,
                    compressed_size=info.compress_size,
                    mtime=mtime,
                    mtime_timezone=None,
                    permissions=permissions or None,
                    compression=method,
                    encrypted=encrypted,
                    link_target=link_target,
                    checksum_algorithm="crc32",
                    checksum_value=f"{info.CRC & 0xFFFFFFFF:08x}",
                    filename_encoding=encoding,
                )
            )
        return _stamp(members, self.display_path)

    def _read_link(self, info: zipfile.ZipInfo) -> str | None:
        try:
            with self._zip.open(info, pwd=self._pwd()) as handle:
                return handle.read().decode("utf-8", errors="replace")
        except (RuntimeError, zipfile.BadZipFile, NotImplementedError):
            return None

    def open_member(
        self, member: Member, budget: Budget, stop_at: int | None = None
    ) -> CountingReader:
        """Stream a ZIP member."""
        if member.member_type == "symlink":
            raise AppError(
                f"{member.path} is a symbolic link"
                + (f" to {member.link_target}" if member.link_target else ""),
                ExitCode.UNSUPPORTED,
            )
        if member.member_type != "file":
            raise AppError(f"{member.path} is not a regular file", ExitCode.UNSUPPORTED)
        info = self._zip.infolist()[member.index - 1]
        if info.compress_type == 99 or (info.compress_type not in _ZIP_METHODS):
            raise AppError(
                f"unsupported compression for {member.path}",
                ExitCode.UNSUPPORTED,
            )
        if stop_at is None:
            budget.check_declared(member.size)
        else:
            budget.check_declared(min(member.size or stop_at, stop_at))
        try:
            raw = self._zip.open(info, pwd=self._pwd())
        except RuntimeError as exc:
            _raise_zip_password(exc, bool(self._password))
        except NotImplementedError as exc:
            raise AppError(f"unsupported zip feature: {exc}", ExitCode.UNSUPPORTED) from exc
        return CountingReader(raw, budget, stop_at)

    def _pwd(self) -> bytes | None:
        if self._password is None:
            return None
        return self._password.encode("utf-8")


def _raise_zip_password(exc: RuntimeError, supplied: bool) -> None:
    text = str(exc).lower()
    if "password required" in text or (not supplied and "encrypted" in text):
        raise AppError("password required", ExitCode.PASSWORD) from exc
    if "bad password" in text or "bad crc" in text:
        raise AppError("incorrect password", ExitCode.PASSWORD) from exc
    raise AppError(f"zip member could not be read: {exc}", ExitCode.CORRUPT) from exc


class TarSession(ArchiveSession):
    """TAR and compressed TAR via the standard library, plus zstandard when needed."""

    backend_name = "tarfile"
    backend_version = f"python-{sys.version.split()[0]}"

    def __init__(self, path: Path, display_path: str, password: str | None, format_id: str) -> None:
        super().__init__(path, display_path, password)
        self.format_id = format_id
        self.random_access = format_id == "tar"
        if format_id != "tar":
            self.limitations.append(
                "Compressed TAR members are reached by sequential decompression. "
                "Per-member compressed sizes are not available."
            )
        self.limitations.append(
            "TAR filenames are decoded as UTF-8 with surrogateescape. "
            "The format does not always declare an encoding."
        )
        if format_id == "tar.zst":
            self.limitations.append("tar.zst is streamed from the start for every member read.")
        self.compression = {
            "tar": None,
            "tar.gz": "gzip",
            "tar.bz2": "bzip2",
            "tar.xz": "xz",
            "tar.zst": "zstd",
        }[format_id]
        # Prove the archive opens, then reopen on each operation.
        handle, owned = self._open_tar()
        handle.close()
        if owned is not None:
            owned.close()

    def _open_tar(self) -> tuple[tarfile.TarFile, IO[bytes] | None]:
        try:
            if self.format_id == "tar.zst":
                import zstandard

                raw = self.path.open("rb")
                try:
                    reader = zstandard.ZstdDecompressor().stream_reader(raw)
                    handle = tarfile.open(  # noqa: SIM115
                        fileobj=reader, mode="r|", encoding="utf-8", errors="surrogateescape"
                    )
                except (zstandard.ZstdError, tarfile.TarError, OSError, EOFError, ValueError):
                    raw.close()
                    raise
                return handle, raw
            modes: dict[str, Literal["r:", "r:gz", "r:bz2", "r:xz"]] = {
                "tar": "r:",
                "tar.gz": "r:gz",
                "tar.bz2": "r:bz2",
                "tar.xz": "r:xz",
            }
            handle = tarfile.open(  # noqa: SIM115
                self.path, modes[self.format_id], encoding="utf-8", errors="surrogateescape"
            )
            return handle, None
        except ImportError as exc:
            raise AppError("zstandard is not installed", ExitCode.UNSUPPORTED) from exc
        except (tarfile.TarError, OSError, EOFError, ValueError) as exc:
            raise AppError(f"tar archive is corrupt or truncated: {exc}", ExitCode.CORRUPT) from exc

    def close(self) -> None:
        """Tar handles are opened per operation and closed there."""

    def _load_members(self) -> list[Member]:
        members: list[Member] = []
        handle, owned = self._open_tar()
        index = 0
        try:
            for info in handle:
                index += 1
                members.append(_tar_member(index, info))
        except (tarfile.TarError, OSError) as exc:
            raise AppError(f"tar archive is corrupt or truncated: {exc}", ExitCode.CORRUPT) from exc
        finally:
            handle.close()
            if owned is not None:
                owned.close()
        return _stamp(members, self.display_path)

    def open_member(
        self, member: Member, budget: Budget, stop_at: int | None = None
    ) -> CountingReader:
        """Stream a TAR member, scanning from the start when the stream is sequential."""
        if member.member_type == "symlink":
            raise AppError(
                f"{member.path} is a symbolic link to "
                f"{member.link_target or 'an unspecified target'}",
                ExitCode.UNSUPPORTED,
            )
        if member.member_type == "hardlink":
            raise AppError(
                f"{member.path} is a hard link to {member.link_target or 'an unspecified target'}",
                ExitCode.UNSUPPORTED,
            )
        if member.member_type != "file":
            raise AppError(f"{member.path} is not a regular file", ExitCode.UNSUPPORTED)
        if stop_at is None:
            budget.check_declared(member.size)
        else:
            budget.check_declared(min(member.size or stop_at, stop_at))
        handle, owned = self._open_tar()
        seen = 0
        try:
            for info in handle:
                if info.name != member.path:
                    continue
                seen += 1
                if seen != member.occurrence:
                    continue
                extracted = handle.extractfile(info)
                if extracted is None:
                    raise AppError(f"{member.path} is not a regular file", ExitCode.UNSUPPORTED)
                return _OwnedReader(extracted, budget, stop_at, handle, owned)
        except AppError:
            handle.close()
            if owned is not None:
                owned.close()
            raise
        except (tarfile.TarError, OSError) as exc:
            handle.close()
            if owned is not None:
                owned.close()
            raise AppError(f"tar member could not be read: {exc}", ExitCode.CORRUPT) from exc
        handle.close()
        if owned is not None:
            owned.close()
        raise AppError(f"member not found: {member.path}", ExitCode.NOT_FOUND)


class _OwnedReader(CountingReader):
    """A member stream that also owns the archive it was opened from."""

    def __init__(
        self,
        raw: IO[bytes],
        budget: Budget,
        stop_at: int | None,
        archive: tarfile.TarFile,
        owned: IO[bytes] | None,
    ) -> None:
        super().__init__(raw, budget, stop_at)
        self._archive = archive
        self._owned_input = owned

    def close(self) -> None:
        """Close the member stream and the archive behind it."""
        if self._closed:
            return
        super().close()
        self._archive.close()
        if self._owned_input is not None:
            self._owned_input.close()


def _tar_member(index: int, info: tarfile.TarInfo) -> Member:
    if info.issym():
        member_type = "symlink"
    elif info.islnk():
        member_type = "hardlink"
    elif info.isdir():
        member_type = "directory"
    elif info.isfile():
        member_type = "file"
    else:
        member_type = "other"
    mtime = datetime.fromtimestamp(info.mtime, tz=UTC) if info.mtime else None
    encoding = None if any(0xD800 <= ord(char) <= 0xDFFF for char in info.name) else None
    return Member(
        index=index,
        path=info.name,
        normalised_path=info.name.replace("\\", "/"),
        member_type=member_type,
        size=0 if info.isdir() else info.size,
        compressed_size=None,
        mtime=mtime,
        mtime_timezone="UTC" if mtime else None,
        permissions=info.mode,
        compression=None,
        encrypted=False,
        link_target=info.linkname or None,
        filename_encoding=encoding,
    )


class SingleSession(ArchiveSession):
    """One compressed stream with a synthetic member name."""

    random_access = True

    def __init__(
        self,
        path: Path,
        display_path: str,
        password: str | None,
        format_id: str,
        opener: Callable[[Path], IO[bytes]],
        declared_size: int | None,
    ) -> None:
        super().__init__(path, display_path, password)
        self.format_id = format_id
        self.backend_name = format_id
        self.backend_version = f"python-{sys.version.split()[0]}"
        self._opener = opener
        self._declared_size = declared_size
        self.compression = format_id
        self.limitations.append(
            "This format stores one data stream and does not contain filenames or directories."
        )
        if format_id == "gzip":
            self.limitations.append("The gzip uncompressed size is stored modulo 2^32.")
        name = path.name
        for suffix in (".gz", ".bz2", ".xz", ".zst", ".zstd"):
            if name.lower().endswith(suffix):
                name = name[: -len(suffix)]
                break
        if not name:
            name = "content"
        self._member_name = name

    def _load_members(self) -> list[Member]:
        member = Member(
            index=1,
            path=self._member_name,
            normalised_path=self._member_name,
            member_type="file",
            size=self._declared_size,
            compressed_size=self.path.stat().st_size,
            compression=self.format_id,
            encrypted=False,
        )
        return _stamp([member], self.display_path)

    def open_member(
        self, member: Member, budget: Budget, stop_at: int | None = None
    ) -> CountingReader:
        """Stream the single decompressed payload."""
        if stop_at is None:
            budget.check_declared(member.size)
        else:
            budget.check_declared(min(member.size or stop_at, stop_at))
        try:
            raw = self._opener(self.path)
        except (OSError, EOFError, gzip.BadGzipFile, lzma.LZMAError, ValueError) as exc:
            raise AppError(f"{self.format_id} stream is corrupt: {exc}", ExitCode.CORRUPT) from exc
        return CountingReader(raw, budget, stop_at)


class SevenZipSession(ArchiveSession):
    """7z via py7zr. Member reads are materialised up to the size limit."""

    format_id = "7z"
    backend_name = "py7zr"
    random_access = False

    def __init__(self, path: Path, display_path: str, password: str | None) -> None:
        super().__init__(path, display_path, password)
        try:
            import py7zr
        except ImportError as exc:
            raise AppError("py7zr is not installed", ExitCode.UNSUPPORTED) from exc
        self._py7zr = py7zr
        self.backend_version = _dist_version("py7zr")
        self.limitations.append(
            "Solid 7z archives may decompress more than the requested member. "
            "The member is materialised in memory up to the configured size limit. "
            "Random access and zero temporary memory use are not promised."
        )
        try:
            archive = py7zr.SevenZipFile(path, mode="r", password=password)
            try:
                self._infos = list(archive.list())
                self.comment = None
            finally:
                archive.close()
        except py7zr.exceptions.PasswordRequired as exc:
            raise AppError("password required", ExitCode.PASSWORD) from exc
        except py7zr.exceptions.Bad7zFile as exc:
            raise AppError(f"7z archive is corrupt or truncated: {exc}", ExitCode.CORRUPT) from exc
        except py7zr.exceptions.ArchiveError as exc:
            _raise_seven_password(exc, bool(password))

    def _load_members(self) -> list[Member]:
        members: list[Member] = []
        for index, info in enumerate(self._infos, start=1):
            if info.is_directory:
                member_type = "directory"
            elif info.is_symlink:
                member_type = "symlink"
            elif info.is_file:
                member_type = "file"
            else:
                member_type = "other"
            mtime = info.creationtime
            members.append(
                Member(
                    index=index,
                    path=info.filename,
                    normalised_path=info.filename.replace("\\", "/"),
                    member_type=member_type,
                    size=0 if info.is_directory else info.uncompressed,
                    compressed_size=info.compressed,
                    mtime=mtime,
                    mtime_timezone="UTC"
                    if mtime is not None and mtime.tzinfo is not None
                    else None,
                    compression="7z",
                    encrypted=None,
                    checksum_algorithm="crc32" if info.crc32 is not None else None,
                    checksum_value=f"{info.crc32 & 0xFFFFFFFF:08x}"
                    if info.crc32 is not None
                    else None,
                )
            )
        return _stamp(members, self.display_path)

    def open_member(
        self, member: Member, budget: Budget, stop_at: int | None = None
    ) -> CountingReader:
        """Materialise one 7z member up to the budget and return it as a stream."""
        if member.member_type != "file":
            raise AppError(f"{member.path} is not a regular file", ExitCode.UNSUPPORTED)
        limit = stop_at if stop_at is not None else member.size
        if limit is None:
            limit = budget.limits.max_member_bytes or budget.limits.max_decompressed_bytes
        budget.check_declared(min(member.size, limit) if member.size is not None else limit)
        factory = self._py7zr.io.BytesIOFactory(limit)
        try:
            archive = self._py7zr.SevenZipFile(
                self.path,
                mode="r",
                password=self._password,
                max_extract_size=limit,
            )
            try:
                archive.extract(targets=[member.path], factory=factory)
            finally:
                archive.close()
        except self._py7zr.exceptions.PasswordRequired as exc:
            raise AppError("password required", ExitCode.PASSWORD) from exc
        except self._py7zr.exceptions.DecompressionBombError as exc:
            raise AppError("decompressed byte budget exceeded", ExitCode.LIMIT) from exc
        except self._py7zr.exceptions.UnsupportedCompressionMethodError as exc:
            raise AppError(f"unsupported 7z compression: {exc}", ExitCode.UNSUPPORTED) from exc
        except self._py7zr.exceptions.CrcError as exc:
            if self._password:
                raise AppError("incorrect password", ExitCode.PASSWORD) from exc
            raise AppError(f"7z member failed integrity: {exc}", ExitCode.CORRUPT) from exc
        except self._py7zr.exceptions.ArchiveError as exc:
            _raise_seven_password(exc, bool(self._password))
        try:
            handle = factory.get(member.path)
        except KeyError as exc:
            raise AppError(f"7z member was not produced: {member.path}", ExitCode.CORRUPT) from exc
        handle.seek(0)
        data = handle.read()
        self.materialised = True
        return CountingReader(io.BytesIO(data), budget, stop_at)


def _raise_seven_password(exc: Exception, supplied: bool) -> None:
    text = str(exc).lower()
    if "password" in text and not supplied:
        raise AppError("password required", ExitCode.PASSWORD) from exc
    if "password" in text:
        raise AppError("incorrect password", ExitCode.PASSWORD) from exc
    raise AppError(f"7z archive could not be read: {exc}", ExitCode.CORRUPT) from exc


class RarSession(ArchiveSession):
    """Read-only RAR via rarfile and an external unrar-compatible tool."""

    format_id = "rar"
    backend_name = "rarfile"
    random_access = False

    def __init__(self, path: Path, display_path: str, password: str | None) -> None:
        super().__init__(path, display_path, password)
        try:
            import rarfile
        except ImportError as exc:
            raise AppError("rarfile is not installed", ExitCode.UNSUPPORTED) from exc
        self._rarfile = rarfile
        self.backend_version = _dist_version("rarfile")
        tool = _rar_tool(rarfile)
        if tool is None:
            raise AppError(
                "RAR reading needs an external unrar, unar, 7z, or bsdtar executable",
                ExitCode.UNSUPPORTED,
            )
        self.limitations.append(
            f"RAR support is read-only and uses the external tool {tool}. "
            "Random access is not promised."
        )
        try:
            self._rar = rarfile.RarFile(path)
            if password:
                self._rar.setpassword(password)
        except rarfile.NeedFirstVolume as exc:
            raise AppError(f"rar archive is incomplete: {exc}", ExitCode.CORRUPT) from exc
        except rarfile.Error as exc:
            _raise_rar(exc, bool(password))

    def close(self) -> None:
        """Close the rar handle."""
        self._rar.close()

    def _load_members(self) -> list[Member]:
        members: list[Member] = []
        for index, info in enumerate(self._rar.infolist(), start=1):
            if info.isdir():
                member_type = "directory"
            elif info.is_symlink():
                member_type = "symlink"
            elif info.is_file():
                member_type = "file"
            else:
                member_type = "other"
            mtime = None
            if info.date_time and info.date_time[0] > 1980:
                try:
                    mtime = datetime(*info.date_time)
                except ValueError:
                    mtime = None
            members.append(
                Member(
                    index=index,
                    path=info.filename,
                    normalised_path=info.filename.replace("\\", "/"),
                    member_type=member_type,
                    size=0 if info.isdir() else info.file_size,
                    compressed_size=info.compress_size,
                    mtime=mtime,
                    compression="rar",
                    encrypted=bool(getattr(info, "needs_password", lambda: False)()),
                    link_target=getattr(info, "link_target", None) or None,
                    checksum_algorithm="crc32" if getattr(info, "CRC", None) is not None else None,
                    checksum_value=(
                        f"{info.CRC & 0xFFFFFFFF:08x}"
                        if getattr(info, "CRC", None) is not None
                        else None
                    ),
                )
            )
        return _stamp(members, self.display_path)

    def open_member(
        self, member: Member, budget: Budget, stop_at: int | None = None
    ) -> CountingReader:
        """Stream a RAR member through the external tool."""
        if member.member_type != "file":
            raise AppError(f"{member.path} is not a regular file", ExitCode.UNSUPPORTED)
        if stop_at is None:
            budget.check_declared(member.size)
        else:
            budget.check_declared(min(member.size or stop_at, stop_at))
        info = self._rar.infolist()[member.index - 1]
        try:
            raw = self._rar.open(info)
        except self._rarfile.Error as exc:
            _raise_rar(exc, bool(self._password))
        return CountingReader(raw, budget, stop_at)


def _raise_rar(exc: Exception, supplied: bool) -> None:
    text = str(exc).lower()
    if "password" in text and not supplied:
        raise AppError("password required", ExitCode.PASSWORD) from exc
    if "password" in text:
        raise AppError("incorrect password", ExitCode.PASSWORD) from exc
    raise AppError(f"rar archive could not be read: {exc}", ExitCode.CORRUPT) from exc


def _dist_version(name: str) -> str:
    try:
        import importlib.metadata

        return importlib.metadata.version(name)
    except importlib.metadata.PackageNotFoundError:
        return "unknown"


def _rar_tool(module: object) -> str | None:
    try:
        setup = module.tool_setup(force=True)  # type: ignore[attr-defined]
    except Exception:
        return None
    return str(getattr(setup, "name", None) or getattr(module, "UNRAR_TOOL", None) or "")


def open_format(
    format_id: str,
    path: Path,
    *,
    display_path: str,
    password: str | None,
) -> ArchiveSession:
    """Open ``path`` with the backend for ``format_id``."""
    if format_id == "zip":
        return ZipSession(path, display_path, password)
    if format_id in {"tar", "tar.gz", "tar.bz2", "tar.xz", "tar.zst"}:
        return TarSession(path, display_path, password, format_id)
    if format_id == "7z":
        return SevenZipSession(path, display_path, password)
    if format_id == "rar":
        return RarSession(path, display_path, password)
    if format_id == "gzip":
        return SingleSession(
            path,
            display_path,
            password,
            format_id,
            lambda item: cast(IO[bytes], gzip.open(item, "rb")),
            _gzip_isize(path),
        )
    if format_id == "bzip2":
        return SingleSession(
            path,
            display_path,
            password,
            format_id,
            lambda item: cast(IO[bytes], bz2.open(item, "rb")),
            None,
        )
    if format_id == "xz":
        return SingleSession(
            path,
            display_path,
            password,
            format_id,
            lambda item: cast(IO[bytes], lzma.open(item, "rb")),
            None,
        )
    if format_id == "zstd":
        return SingleSession(path, display_path, password, format_id, _zstd_open, _zstd_size(path))
    raise AppError(f"unsupported archive format: {format_id}", ExitCode.UNSUPPORTED)


def _gzip_isize(path: Path) -> int | None:
    try:
        with path.open("rb") as handle:
            handle.seek(-4, io.SEEK_END)
            tail = handle.read(4)
    except OSError:
        return None
    if len(tail) < 4:
        return None
    return int.from_bytes(tail, "little")


def _zstd_open(path: Path) -> BinaryIO:
    import zstandard

    raw = path.open("rb")
    reader = zstandard.ZstdDecompressor().stream_reader(raw)
    return io.BufferedReader(_ClosingReader(reader, raw))


def _zstd_size(path: Path) -> int | None:
    try:
        import zstandard
    except ImportError:
        return None
    try:
        with path.open("rb") as handle:
            params = zstandard.get_frame_parameters(handle.read(64))
        if params.content_size == zstandard.CONTENTSIZE_UNKNOWN:
            return None
        return int(params.content_size)
    except (OSError, zstandard.ZstdError):
        return None


class _ClosingReader(io.RawIOBase):
    """Close both a zstandard reader and the file underneath it."""

    def __init__(self, reader: BinaryIO, raw: BinaryIO) -> None:
        self._reader = reader
        self._raw = raw

    def readable(self) -> bool:
        return True

    def read(self, size: int = -1) -> bytes:
        return self._reader.read(size)

    def close(self) -> None:
        self._reader.close()
        self._raw.close()
        super().close()


def capabilities() -> list[Capability]:
    """Return runtime capabilities for every known format."""
    zstd_version = _dist_version("zstandard")
    py7zr_ok = _importable("py7zr")
    rar_ok = _importable("rarfile")
    rar_tool = None
    if rar_ok:
        import rarfile

        rar_tool = _rar_tool(rarfile)
    rows = [
        _zip_capability(),
        _tar_capability("tar", True),
        _tar_capability("tar.gz", False),
        _tar_capability("tar.bz2", False),
        _tar_capability("tar.xz", False),
        _tar_capability("tar.zst", False, extra=["Requires the zstandard package."]),
        _seven_capability(py7zr_ok),
        _rar_capability(rar_ok, rar_tool),
        _single_capability("gzip", "gzip", True),
        _single_capability("bzip2", "bz2", True),
        _single_capability("xz", "lzma", True),
        _single_capability(
            "zstd",
            "zstandard",
            zstd_version != "unknown",
            version=zstd_version,
            optional=True,
        ),
    ]
    return rows


def _importable(name: str) -> bool:
    try:
        __import__(name)
    except ImportError:
        return False
    return True


def _zip_capability() -> Capability:
    return Capability(
        format_id="zip",
        detection=True,
        inspection=True,
        listing=True,
        streaming=True,
        extraction=True,
        integrity=True,
        encryption=True,
        nested=True,
        random_access=True,
        backend="zipfile",
        backend_version=f"python-{sys.version.split()[0]}",
        available=True,
        optional=False,
        limitations=[
            "AES-encrypted ZIP is not supported.",
            "Traditional ZipCrypto is supported and is not strong encryption.",
        ],
    )


def _tar_capability(
    format_id: str, random_access: bool, extra: list[str] | None = None
) -> Capability:
    limits = [
        "Encrypted TAR is not supported.",
        "Per-member compressed sizes are not available.",
    ]
    if not random_access:
        limits.append("Members are reached by sequential decompression.")
    if extra:
        limits.extend(extra)
    return Capability(
        format_id=format_id,
        detection=True,
        inspection=True,
        listing=True,
        streaming=True,
        extraction=True,
        integrity=True,
        encryption=False,
        nested=True,
        random_access=random_access,
        backend="tarfile" if format_id != "tar.zst" else "tarfile+zstandard",
        backend_version=f"python-{sys.version.split()[0]}",
        available=True,
        optional=format_id == "tar.zst",
        limitations=limits,
    )


def _seven_capability(available: bool) -> Capability:
    return Capability(
        format_id="7z",
        detection=True,
        inspection=available,
        listing=available,
        streaming=available,
        extraction=available,
        integrity=available,
        encryption=available,
        nested=available,
        random_access=False,
        backend="py7zr",
        backend_version=_dist_version("py7zr") if available else "not installed",
        available=available,
        optional=True,
        limitations=[
            "Solid archives may decompress additional data.",
            "Member access materialises the member up to the size limit.",
        ],
    )


def _rar_capability(package: bool, tool: str | None) -> Capability:
    available = package and bool(tool)
    return Capability(
        format_id="rar",
        detection=True,
        inspection=available,
        listing=available,
        streaming=available,
        extraction=available,
        integrity=available,
        encryption=available,
        nested=available,
        random_access=False,
        backend="rarfile",
        backend_version=_dist_version("rarfile") if package else "not installed",
        available=available,
        optional=True,
        limitations=[
            "Read-only.",
            "Requires the rarfile package and an external unrar, unar, 7z, or bsdtar tool.",
            f"Active tool: {tool or 'none'}.",
        ],
    )


def _single_capability(
    format_id: str,
    backend: str,
    available: bool,
    version: str | None = None,
    optional: bool = False,
) -> Capability:
    return Capability(
        format_id=format_id,
        detection=True,
        inspection=available,
        listing=available,
        streaming=available,
        extraction=available,
        integrity=available,
        encryption=False,
        nested=available,
        random_access=True,
        backend=backend,
        backend_version=version or f"python-{sys.version.split()[0]}",
        available=available,
        optional=optional,
        limitations=[
            "One anonymous data stream. No directory listing is stored in the format.",
            "Uncompressed size may be unavailable or, for gzip, modulo 2^32.",
        ],
    )
