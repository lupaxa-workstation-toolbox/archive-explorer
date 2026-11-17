"""Behaviour tests for Archive Explorer."""

from __future__ import annotations

import base64
import hashlib
import io
import json
import tarfile
import zipfile
from pathlib import Path

from lupaxa.archive_explorer.cli import main

_ENCRYPTED_ZIP = base64.b64decode(
    "UEsDBAoACQAAAHhYcV0XGEwNGAAAAAwAAAAKABwAc2VjcmV0LnR4dFVUCQADlDT8apQ0"
    "/Gp1eAsAAQT1AQAABBQAAABnaAF1/9FD1Sj0i7chKKtswXFLAQQLHfZQSwcIFxhMDRgA"
    "AAAMAAAAUEsBAh4DCgAJAAAAeFhxXRcYTA0YAAAADAAAAAoAGAAAAAAAAQAAAKSBAAAA"
    "AHNlY3JldC50eHRVVAUAA5Q0/Gp1eAsAAQT1AQAABBQAAABQSwUGAAAAAAEAAQBQAAAA"
    "bAAAAAAA"
)


def _run(args: list[str]) -> tuple[int, bytes, str]:
    stdout = io.BytesIO()
    stderr = io.StringIO()
    code = main(args, stdout=stdout, stderr=stderr, stdin=io.StringIO(""), environ={})
    return code, stdout.getvalue(), stderr.getvalue()


def _zip(path: Path, files: dict[str, bytes]) -> None:
    with zipfile.ZipFile(path, "w") as archive:
        for name, data in files.items():
            archive.writestr(name, data)


def _tar(path: Path, files: dict[str, bytes], mode: str = "w") -> None:
    with _open_tar(path, mode == "w:gz") as archive:
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mtime = 1_700_000_000
            archive.addfile(info, io.BytesIO(data))


def _open_tar(path: Path, compressed: bool) -> tarfile.TarFile:
    if compressed:
        return tarfile.open(path, "w:gz")  # noqa: SIM115
    return tarfile.open(path, "w")  # noqa: SIM115


def test_inspect_list_find_and_unchanged_source(tmp_path: Path) -> None:
    archive = tmp_path / "backup.zip"
    _zip(archive, {"docs/readme.txt": b"hello", "notes.txt": b"database_url = secret"})
    before = hashlib.sha256(archive.read_bytes()).digest()
    code, out, err = _run(["inspect", str(archive), "--json"])
    assert code == 0, err
    payload = json.loads(out)
    assert payload["schema_version"] == "1.0"
    assert payload["archive"]["format"] == "zip"
    assert payload["archive"]["file_count"] == 2
    code, out, err = _run(["list", str(archive), "--path", "docs"])
    assert code == 0, err
    assert b"docs/readme.txt" in out
    code, out, err = _run(["find", str(archive), "*.txt", "--json"])
    assert json.loads(out)["match_count"] == 2
    code, out, err = _run(["grep", str(archive), "database_url"])
    assert b"notes.txt:1:" in out
    assert hashlib.sha256(archive.read_bytes()).digest() == before


def test_cat_exact_bytes_and_duplicate_selection(tmp_path: Path) -> None:
    archive = tmp_path / "dup.zip"
    payload = bytes(range(256))
    with zipfile.ZipFile(archive, "w") as handle:
        handle.writestr("bin.dat", payload)
        handle.writestr("same.txt", b"one")
        handle.writestr("same.txt", b"two")
    code, out, err = _run(["cat", str(archive), "--path", "bin.dat"])
    assert code == 0, err
    assert out == payload
    code, _out, err = _run(["cat", str(archive), "--path", "same.txt"])
    assert code == 10
    assert "ambiguous" in err
    code, out, err = _run(["cat", str(archive), "--path", "same.txt@@2"])
    assert out == b"two"


def test_nested_access_extract_and_safety(tmp_path: Path) -> None:
    inner = tmp_path / "inner.tar"
    _tar(inner, {"config/settings.toml": b"database_url = x\n"})
    outer = tmp_path / "outer.zip"
    _zip(outer, {"projects/source.tar": inner.read_bytes()})
    code, out, err = _run(
        ["cat", str(outer), "--path", "projects/source.tar::config/settings.toml"]
    )
    assert code == 0, err
    assert out == b"database_url = x\n"
    destination = tmp_path / "settings.toml"
    code, _out, err = _run(
        [
            "get",
            str(outer),
            "--path",
            "projects/source.tar::config/settings.toml",
            "--output",
            str(destination),
        ]
    )
    assert code == 0, err
    assert destination.read_bytes() == b"database_url = x\n"
    slip = tmp_path / "slip.zip"
    _zip(slip, {"../evil.txt": b"nope"})
    code, _out, err = _run(
        ["get", str(slip), "--path", "../evil.txt", "--dest", str(tmp_path / "out")]
    )
    assert code == 4
    assert not (tmp_path / "evil.txt").exists()
    code, out, err = _run(["safety", str(slip), "--json"])
    assert code == 0, err
    payload = json.loads(out)
    assert "path.traversal" in {item["id"] for item in payload["findings"]}


def test_diff_duplicates_password_and_formats(tmp_path: Path) -> None:
    old = tmp_path / "old.zip"
    new = tmp_path / "new.zip"
    _zip(old, {"keep.txt": b"same", "gone.txt": b"old"})
    _zip(new, {"keep.txt": b"same", "fresh.txt": b"new"})
    code, out, err = _run(["diff", str(old), str(new), "--mode", "content"])
    assert code == 0, err
    assert b"fresh.txt" in out
    assert b"gone.txt" in out
    archive = tmp_path / "dups.zip"
    _zip(archive, {"a.txt": b"same-bytes", "b.txt": b"same-bytes"})
    code, out, err = _run(["duplicates", str(archive), "--json"])
    group = json.loads(out)["groups"][0]
    assert group["occurrences"] == 2
    assert group["estimated_archive_savings"] is None
    secret = tmp_path / "secret.zip"
    secret.write_bytes(_ENCRYPTED_ZIP)
    code, _out, err = _run(["cat", str(secret), "--path", "secret.txt"])
    assert code == 6
    password = tmp_path / "password.txt"
    password.write_text("hunter2\n", encoding="utf-8")
    code, out, err = _run(
        ["cat", str(secret), "--path", "secret.txt", "--password-file", str(password)]
    )
    assert code == 0, err
    assert out == b"secret-value"
    code, out, err = _run(["formats", "--json"])
    formats = {item["format"] for item in json.loads(out)["formats"]}
    assert "zip" in formats
    assert "7z" in formats


def test_limits_config_and_misleading_extension(tmp_path: Path) -> None:
    archive = tmp_path / "notes.txt.gz"
    import gzip

    archive.write_bytes(gzip.compress(b"plain-text"))
    code, out, err = _run(["cat", str(archive), "--path", "notes.txt"])
    assert code == 0, err
    assert out == b"plain-text"
    tar_path = tmp_path / "pack.tar.gz"
    _tar(tar_path, {"inside.txt": b"tar-member"}, mode="w:gz")
    renamed = tmp_path / "pack.zip"
    renamed.write_bytes(tar_path.read_bytes())
    code, _out, err = _run(["list", str(renamed), "--archive-format", "zip"])
    assert code == 2
    code, _out, err = _run(["cat", str(renamed), "--path", "inside.txt", "--max-size", "1B"])
    assert code == 7
    config = tmp_path / "bad.toml"
    config.write_text("unknown = true\n", encoding="utf-8")
    code, _out, err = _run(["formats", "--config", str(config)])
    assert code == 2
