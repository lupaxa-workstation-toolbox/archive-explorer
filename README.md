<p align="center">
  <a href="https://github.com/lupaxa-workstation-toolbox">
    <img src="https://raw.githubusercontent.com/the-lupaxa-project/brand-assets/master/logos/organisations/workstation-toolbox/readme-logo.png" alt="Workstation Toolbox" />
  </a>
</p>

<h1 align="center">Archive Explorer</h1>

Archive Explorer reads compressed archives without unpacking them. Listing, searching,
streaming, and comparing never modify the source file, and a command decompresses a member only
when it needs those bytes.

It works offline. A configuration file is optional. This README is the usage guide and the developer guide.

## What it Does

- Inspect size, dates, compression, and member counts.
- List members and show a virtual directory tree.
- Search by name, path, size, type, and date.
- Search text inside members.
- Stream one member to standard output.
- Extract a selection into a destination you choose.
- Compare two archives and find duplicate contents.
- Walk nested archives, assess extraction risks, and test integrity.
- Write text, JSON, JSON Lines, Markdown, and HTML reports.

Listing an archive reads metadata. Decompressing a member reads that member's bytes for `cat`,
`grep`, hashing, or a full integrity test. Extracting a member writes it under a destination after
path checks. Archive Explorer does not unpack the whole archive as a way to answer those
questions.

> **Note:** A compressed tar, a solid 7z archive, and a single-stream gzip file may have to be read from the start before one member is available. The tool reports that limit. It does not pretend every format is random-access.

## Requirements

- Python 3.11 or newer
- macOS, Linux, or Windows

ZIP, tar, gzip, bzip2, xz, zstandard, and 7z are included with the package. RAR reading also
needs `unrar`, `unar`, `7z`, or `bsdtar` on `PATH`. ZIP encryption is ZipCrypto. AES is reported as unsupported.

The format comes from the file signature. The extension is a hint. A file named `.zip` that is
actually gzip is not opened as ZIP. `--archive-format` must agree with the signature unless you also pass `--force`.

## Install

```bash
pip install lupaxa-archive-explorer
archive-explorer --help
```

Every command accepts `--help`.

## Quick Start

```bash
archive-explorer inspect download.zip
archive-explorer tree download.zip --depth 3
archive-explorer safety download.zip
archive-explorer cat backup.zip --path config/settings.toml
```

`cat` writes only the member's bytes to standard output. There is no banner and no added newline.
Diagnostics, warnings, and progress go to standard error. `--json` and `--jsonl` follow the same split for
the other commands.

```bash
archive-explorer cat backup.zip \
    --path config/settings.toml | grep database
```

Binary output to a terminal requires `--force`. A pipe or a redirect does not. A broken pipe exits 0.

## Commands

| Command      | Purpose                                          |
| ------------ | ------------------------------------------------ |
| `inspect`    | Statistics, dates, compression, and limitations  |
| `list`       | Member listing, with sort, type, and long format |
| `tree`       | Virtual directory tree                           |
| `find`       | Search members by name, size, type, and date     |
| `grep`       | Search text inside members                       |
| `cat`        | Stream one member to standard output             |
| `get`        | Extract selected members                         |
| `diff`       | Compare two archives                             |
| `duplicates` | Exact duplicate contents                         |
| `nested`     | Archives stored inside an archive                |
| `safety`     | Extraction risks                                 |
| `test`       | Structural or full integrity test                |
| `report`     | Text, JSON, JSON Lines, Markdown, or HTML        |
| `formats`    | Backends available in this process               |
| `version`    | Version string                                   |

### Inspect, List, and Tree

```bash
archive-explorer inspect backup.tar.gz
archive-explorer inspect package.zip --json --detailed
archive-explorer inspect backup.zip --member projects/source.tar.gz
archive-explorer list backup.zip --path Documents/ --sort size --long
archive-explorer tree backup.zip --depth 3 --sizes
```

`inspect` reports the detected format, compressed size, declared uncompressed size, file and directory
counts, date range, encryption, nested-archive count, backend, and limitations. Declared sizes
come from the archive and can be wrong. A format that does not store a per-member compressed
size shows that field as unavailable.

`--detailed` adds compression methods, comments, and duplicate paths when the backend can see them. `--member`
inspects one nested archive instead of the outer file.

`list --sort` accepts `name`, `size`, `date`, `type`, and `ratio`. `--type` accepts `file`, `directory`, `symlink`, `hardlink`, and `other`. `--limit` and
`--offset` page the listing. Duplicate paths stay distinct. The second copy of a path is `name@@2`. A
command that needs one member refuses an ambiguous path.

`tree --depth` is directory depth. It is separate from `--max-depth`, which limits nested archives. The tree is built
from member paths and does not write the archive to disk.

### Find and Grep

```bash
archive-explorer find backup.tar.gz "*.conf"
archive-explorer find backup.zip --min-size 100KB --type file
archive-explorer find backup.zip --modified-after 2025-01-01 --nested
archive-explorer grep backup.tar.gz "database_url" --include "*.toml"
archive-explorer grep backup.zip "TODO" --ignore-case --regex
```

On `find`, `--max-size` and `--min-size` filter uncompressed size. The decompressed-byte ceiling on that command is
`--max-member-size`. A pattern matches the file name unless it contains a slash or you pass `--full-path`. `--match all` is the
default and requires every filter. `--match any` keeps a member that satisfies one filter.

`grep` searches literal text unless you pass `--regex`. Likely binary members are skipped unless `--binary` is
set. Control characters other than tab and newline are escaped.

A search with no matches exits 0. `--fail-on-empty` exits 1, which stays separate from the usage and
corruption codes.

### Cat and Get

```bash
archive-explorer cat outer.zip \
    --path "projects/source.tar.gz::config/settings.toml"
archive-explorer get outer.zip \
    --path "projects/source.tar.gz::config/settings.toml" \
    --output settings.toml
archive-explorer get backup.zip --glob "*.conf" --dest ./out
```

Select a member with `--path`, `--index` (1-based), or `--selector`. Use one of those styles at a time. Symbolic
links are not followed. `cat --follow-symlinks` follows a link inside the same archive, stops on a cycle, and
refuses an absolute target or a `..` segment.

One member plus `--output` writes that file. Several members need `--dest`. `--flatten` uses only the file name. `--dry-run`
prints the planned paths and writes nothing. An existing file is left unchanged unless `--force` is
set.

Extraction rejects absolute paths, `..`, and Windows reserved names. The default policy writes
regular files and directories. Symbolic links need `--allow-symlinks`. Hard links need `--allow-hardlinks`. Special files are
refused. Each file is written to a temporary name in the destination and renamed into place.

### Compare, Duplicates, and Reports

```bash
archive-explorer diff old.zip new.zip --mode content
archive-explorer duplicates backup.zip --nested
archive-explorer duplicates backup-a.zip backup-b.zip
archive-explorer safety download.zip --json
archive-explorer test backup.zip --full
archive-explorer report backup.zip --format html --output archive-report.html
archive-explorer formats --json
```

`diff --mode fast` compares paths, types, declared sizes, timestamps, and stored checksums. It does not treat
matching names and sizes as proof of equal contents. `content` hashes regular files with SHA-256. `detailed`
adds a unified diff for text files under the configured size. Binary files are not forced
through that diff.

`duplicates` groups files with the same declared size and the same SHA-256. The redundant-byte figure is
uncompressed size. Estimated archive storage savings are left unknown.

`safety` exits 0 when the scan finishes, including when it found risks. Exit code 4 is an extraction
the policy refused.

> **Note:** A safety scan is not antivirus and does not prove an archive is safe to extract.

`test` without `--full` checks structure. `--full` decompresses regular files and checks a stored checksum
when the backend has one. A passed test is not a statement that the archive was signed.

`report --format` is `text`, `json`, `jsonl`, `markdown`, or `html`. The archive format override is `--archive-format`, so the two options do not
collide. HTML is one self-contained file and does not need a web server.

## Virtual Paths

A nested member is addressed by chaining archives with `::`:

```text
outer.zip::projects/source.tar.gz::config/settings.toml
```

If a real name contains `::`, pass `--selector` with JSON. Each object has `path` or `index`, and may set `occurrence`:

```bash
archive-explorer cat outer.zip --selector \
    '[{"path":"projects/source.tar.gz"},{"path":"config/settings.toml"}]'
```

`name@@2` and `#2` also select occurrence 2. Occurrence numbers start at 1.

## Shared Options

| Option                     | Meaning                                                                        |
| -------------------------- | ------------------------------------------------------------------------------ |
| `--archive-format`         | Require this format. The signature must still match unless `--force` is set.   |
| `--json` / `--jsonl`       | Machine-readable output. Diagnostics stay on standard error.                   |
| `--output`                 | Write the report to a file. `cat` does not use this.                           |
| `--nested` / `--recursive` | Walk archives stored inside the archive.                                       |
| `--max-depth`              | Nested-archive depth.                                                          |
| `--max-size`               | Maximum decompressed bytes for one member. On `find`, this is the size filter. |
| `--max-member-size`        | Same byte ceiling, including on `find`.                                        |
| `--timeout`                | Stop when this many seconds have elapsed.                                      |
| `--verbose` / `--quiet`    | Extra limitations, or no warnings.                                             |
| `--no-colour`              | Plain text.                                                                    |
| `--config`                 | TOML file. Overrides the user file.                                            |
| `--password-file`          | First line of a file.                                                          |
| `--password-stdin`         | Read the password from standard input.                                         |
| `--force`                  | Allow a signature mismatch, a binary `cat` on a terminal, or an overwrite.     |

A size is a byte count or a number with `B`, `KiB`, `MiB`, `GiB`, `KB`, `MB`, or `GB`.

Colour is on when standard output is a terminal. `--no-colour`, `colour = false`, or `NO_COLOR` turns it off.

## Passwords and Limits

The password comes from a prompt, `--password-file`, `--password-stdin`, or `ARCHIVE_EXPLORER_PASSWORD` when `allow_password_env` is true. It is not a command-line
argument, and it is removed from error text. The prompt does not echo.

Default limits cover the whole command, including nested archives:

| Limit                    | Default                                |
| ------------------------ | -------------------------------------- |
| Nested depth             | 5                                      |
| Members visited          | 100,000                                |
| One decompressed member  | 1 GiB                                  |
| Total decompressed bytes | 4 GiB                                  |
| Temporary disk           | 2 GiB                                  |
| Time                     | Off until `--timeout` or `max_seconds` |

Set a byte or count ceiling to `0` to disable that ceiling. Temporary files use mode `0600` and are
removed when the command ends.

User configuration is `$ARCHIVE_EXPLORER_CONFIG` when that variable is set. Otherwise it is `$XDG_CONFIG_HOME/archive-explorer/config.toml`, `~/.config/archive-explorer/config.toml`, or `%APPDATA%\archive-explorer\config.toml` on
Windows. Precedence is the command line, then `--config`, then the user file, then built-in defaults.
Unknown keys are errors. A missing user file is ignored. A missing `--config` path is an error.

## Exit Codes

| Code | Meaning                                                            |
| ---- | ------------------------------------------------------------------ |
| 0    | Success. A search with no matches also exits 0.                    |
| 1    | General failure. `--fail-on-empty` uses this when nothing matched. |
| 2    | Invalid arguments or configuration.                                |
| 3    | Corrupt archive or failed integrity test.                          |
| 4    | Extraction refused by the safety policy.                           |
| 5    | Unsupported format or capability.                                  |
| 6    | Password or decryption failure.                                    |
| 7    | Resource limit exceeded.                                           |
| 8    | Part of the command failed.                                        |
| 9    | Requested member was not found.                                    |
| 10   | The path matches more than one member.                             |

## Development

Clone the repository, then install the makefile skills and the editable package:

```bash
make init
make install-dev
```

`make init` clones [makefile-skills](https://github.com/lupaxa-developers-toolbox/makefile-skills) into `.makefiles/`. That directory is gitignored. `make install-dev` installs this project with the `dev`
extra: pytest, Ruff, mypy, Hatch, and bump-my-version.

Run the tool from the checkout with `archive-explorer`, or with `python -m lupaxa.archive_explorer`. The console script is declared as `archive-explorer = lupaxa.archive_explorer.cli:main`.

### Checks

```bash
make check
make test
make lint
make format
```

`make check` is what CI runs: Ruff, mypy, and pytest. `make test` is pytest alone. `make lint` is the Ruff lint and
format check. `make format` rewrites formatting. Tests build synthetic archives in temporary directories
and do not use the network.

Coverage is part of the pytest options in `pyproject.toml`. `make python-check-all` adds the coverage report and `pip-audit`.

### Version

The version string is `__version__` in `src/lupaxa/archive_explorer/version.py`. Hatch reads that file. Bump it with the makefile targets, for
example `make show-version-flow` and `make bump-minor-rc`. The first version is `0.0.0`. Version tests check the semantic shape. They do
not pin a literal version.

`make help` lists every target.

<a href="https://github.com/the-lupaxa-project">
    <img src="https://raw.githubusercontent.com/the-lupaxa-project/brand-assets/master/logos/components/footer-for-child-orgs.svg" alt="The Lupaxa Project Footer" width="100%" />
</a>
