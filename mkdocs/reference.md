# Reference

## Formats and Backends

The format is chosen from the file signature. The extension is a hint. A `.zip` file whose bytes are
gzip is not opened as ZIP. `--archive-format` must agree with the signature unless you also pass
`--force`.

| Format                     | Backend                   | Notes                                                                                                                                |
| -------------------------- | ------------------------- | ------------------------------------------------------------------------------------------------------------------------------------ |
| ZIP                        | `zipfile`                 | Random access. ZipCrypto can be decrypted. AES (method 99) is reported as unsupported.                                               |
| TAR                        | `tarfile`                 | Sequential. Reopened for each member read.                                                                                           |
| TAR.GZ, TGZ                | `tarfile`                 | Sequential gzip.                                                                                                                     |
| TAR.BZ2, TBZ2              | `tarfile`                 | Sequential bzip2.                                                                                                                    |
| TAR.XZ, TXZ                | `tarfile`                 | Sequential xz.                                                                                                                       |
| TAR.ZST, TZST              | `zstandard` and `tarfile` | Sequential. Needs the `zstandard` package, which is a dependency.                                                                    |
| 7z                         | `py7zr`                   | A requested member is materialised up to the byte budget. Solid archives may decompress more than that member.                       |
| RAR                        | `rarfile`                 | Read-only, and only when `unrar`, `unar`, `7z`, or `bsdtar` is on `PATH`.                                                            |
| GZIP, BZIP2, XZ, Zstandard | stdlib or `zstandard`     | One stream. The virtual member is named from the archive stem plus a conventional extension, such as `notes.txt` for `notes.txt.gz`. |

A backend does not advertise streaming, encryption, or random access it cannot perform.
`archive-explorer formats --json` is the runtime matrix.

## Virtual Paths

A display path chains archives with `::`:

```text
outer.zip::projects/source.tar.gz::config/settings.toml
```

`::` is convenient and ambiguous if a real file name contains those characters. Use `--selector`
when the path itself is untrusted or contains `::`:

```bash
archive-explorer cat outer.zip --selector \
    '[{"path":"projects/source.tar.gz"},{"path":"config/settings.toml"}]'
```

Each object has `path` or `index`, and may set `occurrence` when the same path is stored more than
once. On the command line, `name@@2` is occurrence 2. Occurrence numbers start at 1. An omitted
occurrence is an error when more than one member has that path.

`#N` on a path segment is also occurrence N.

## Resource Limits

Limits apply to the whole command, including nested archives. They are not reset at each level.

| Limit                    | Default                                 |
| ------------------------ | --------------------------------------- |
| Nested depth             | 5                                       |
| Members visited          | 100,000                                 |
| One decompressed member  | 1 GiB                                   |
| Total decompressed bytes | 4 GiB                                   |
| Temporary disk           | 2 GiB                                   |
| Time                     | Off, until `--timeout` or `max_seconds` |

Set a byte or count ceiling to `0` in configuration, or pass `--max-member-size 0`, to disable that
ceiling. That is an explicit action. Time stays off until you set it.

Temporary files are created with mode `0600` under the system temp directory, or `temp_directory`,
and they are removed when the command finishes, including after a handled failure. Nested archives
that cannot be streamed in place are copied there. The tool tells you when that happens.

`worker_count` must be at least 1. Work runs in one thread so output order and the shared byte
budget stay deterministic.

## Safety Rules

Windows path checks run on every operating system. The scan looks for absolute paths, `..`, drive
letters, UNC paths, symlinks and hard links, special files, duplicate paths, case-insensitive
collisions, NFC collisions, reserved Windows names, control characters, long paths, deep paths,
suspicious expansion, huge declared sizes, encryption, unsupported methods, and nested depth.

A suspicious ratio defaults to 100:1 declared expansion on a member of at least 1,000,000
uncompressed bytes. Declared sizes are not trusted on their own. Processing stops when a budget is
exceeded.

Finding ids:

- `path.absolute`, `path.traversal`, `path.windows-drive`, `path.unc`
- `link.symlink`, `link.escapes`, `link.hardlink`, `entry.special`
- `path.duplicate`, `path.case-collision`, `path.unicode-collision`
- `path.reserved-windows`, `path.invalid-characters`, `path.too-long`, `path.deep-nesting`
- `compression.suspicious-ratio`, `compression.excessive-size`, `encryption.present`
- `compression.unsupported`, `structure.malformed`, `bomb.declared`, `bomb.nested`

Severities are `critical`, `high`, `medium`, `low`, `informational`, and `unknown`.

## Integrity

Structural testing lists members. Full testing reads regular files and compares a stored CRC when
the backend recorded one. Tar archives often have no member checksum. Gzip may expose an
uncompressed size, not a content hash. A `passed` outcome means those checks succeeded. It does not
mean the archive was signed.

## Passwords

The password comes from a prompt, `--password-file`, `--password-stdin`, or the environment variable
`ARCHIVE_EXPLORER_PASSWORD` only when `allow_password_env` is true. The prompt does not echo. The
password is not a command-line argument, and it is redacted from errors.

These cases are distinguished: password required, wrong password, unsupported encryption, and a
corrupt encrypted member. Listing a ZIP central directory does not always need the password. Reading
the member does. The error says which one failed.

## JSON

Machine-readable output is UTF-8 JSON. `schema_version` is `"1.0"`. Sizes are bytes. Unknown
metadata is `null`. Timestamps are ISO-8601. `mtime_timezone` is set only when the backend knows the
zone. Tar times are UTC.

```json
{
  "schema_version": "1.0",
  "command": "list",
  "status": "completed",
  "archive": {"path": "backup.zip"},
  "members": [
    {
      "id": "member-000001",
      "path": "config/settings.toml",
      "normalised_path": "config/settings.toml",
      "virtual_path": "backup.zip::config/settings.toml",
      "occurrence": 1,
      "type": "file",
      "size": 2048,
      "compressed_size": null,
      "encrypted": false,
      "inferred": false
    }
  ]
}
```

`status` is `completed`, `partial`, or another terminal state the command sets. `cat` is the
exception: its standard output is raw bytes, not this document.

Progress, banners, and warnings are not mixed into JSON. They go to standard error.

## Configuration

```toml
output_format = "text"
colour = true
max_depth = 5
max_members = 100000
max_member_bytes = 1073741824
max_decompressed_bytes = 4294967296
max_temp_bytes = 2147483648
max_seconds = 60
worker_count = 1
suspicious_ratio = 100
max_path_components = 40
max_line_length = 16384
max_diff_bytes = 2097152
temp_directory = "/tmp"
default_encoding = "utf-8"
encoding_errors = "replace"
hash_algorithm = "sha256"
follow_symlinks = false
allow_password_env = false
report_format = "text"
preferred_backends = ["zipfile", "tarfile", "py7zr"]
```

`color` is accepted as an alias of `colour`. `hash_algorithm` must be `sha256`. `preferred_backends`
names a known backend. It does not override signature detection. `cache_directory` is accepted and
is not used: member contents and archive indexes are not written to a cache.

`output_format` and `report_format` accept `text`, `json`, `jsonl`, `markdown`, and `html`.

## Exit Codes

| Code | Meaning                                                                     |
| ---- | --------------------------------------------------------------------------- |
| 0    | Success. Search commands also use 0 when nothing matched.                   |
| 1    | General failure. `--fail-on-empty` uses this when a search matches nothing. |
| 2    | Invalid arguments or configuration.                                         |
| 3    | Corrupt archive or failed integrity test.                                   |
| 4    | Extraction refused by the safety policy.                                    |
| 5    | Unsupported format or capability.                                           |
| 6    | Password or decryption failure.                                             |
| 7    | Resource limit exceeded.                                                    |
| 8    | Part of the command failed.                                                 |
| 9    | Requested member was not found.                                             |
| 10   | The path matches more than one member.                                      |

## Troubleshooting

**The extension is wrong.** Detection follows the signature. Rename the file or omit
`--archive-format`. `--force` opens a mismatched signature and can produce a corrupt-archive error.

**`cat` looks empty or the shell ate the output.** Binary data on a terminal needs `--force`. In a
pipe, the next program may be waiting for text. Check the exit code and standard error.

**A tar member is slow.** Compressed tar is sequential. Reaching a late member rereads the stream.
That is a format limit, not a missing index.

**RAR says it is unsupported.** Install `unar`, `unrar`, `7z`, or confirm `bsdtar` is on `PATH`,
then run `archive-explorer formats`.

**A nested `::` path fails.** The inner file must itself be an archive the backend can open. A
corrupt inner archive is reported as that member, not as a failure of every other member.

**JSON contains an unexpected banner.** You did not pass `--json` or `--jsonl`. Human text includes
the Archive Explorer heading. `cat` never prints that heading.
