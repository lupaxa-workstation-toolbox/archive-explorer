# Getting Started

## Requirements

Python 3.11 or newer, on macOS, Linux, or Windows. The program does not need a network connection
after it is installed, and it runs with no configuration file.

RAR reading needs an external `unrar`, `unar`, `7z`, or `bsdtar` program. ZIP, tar, gzip, bzip2, xz,
and zstandard are included with the Python package. See the
[format matrix](reference.md#formats-and-backends).

## Install

```bash
pip install lupaxa-archive-explorer
archive-explorer --help
```

From a checkout:

```bash
make init
make install-dev
make check
```

## First Commands

```bash
archive-explorer inspect download.zip
archive-explorer tree download.zip --depth 3
archive-explorer safety download.zip
archive-explorer cat backup.zip --path config/settings.toml
```

`cat` writes only the member's bytes to standard output. Diagnostics go to standard error. `--json`
and `--jsonl` do the same for the other commands: the document is on standard output, and warnings
are on standard error.

## Colour and Quiet Output

Colour is on when standard output is a terminal. `--no-colour`, a false `colour` setting, or the
`NO_COLOR` environment variable turns it off. `--quiet` suppresses warnings. `--verbose` prints
extra limitations, including when a nested archive had to be copied to temporary storage.

## Configuration is Optional

Built-in limits apply until you pass `--config` or create a user file. Precedence is:

1. Command-line options.
2. The file named by `--config`. 3. The user file. 4. Built-in defaults.

The user file is `$ARCHIVE_EXPLORER_CONFIG` when that variable is set. Otherwise it is
`$XDG_CONFIG_HOME/archive-explorer/config.toml`, `~/.config/archive-explorer/config.toml`, or
`%APPDATA%\archive-explorer\config.toml` on Windows. A missing user file is ignored. A missing
`--config` path is an error. Unknown keys are errors. Details are in
[Configuration](reference.md#configuration).
