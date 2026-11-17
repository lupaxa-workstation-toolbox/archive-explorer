# Usage

Every command accepts `--help`. Options that appear on more than one command keep the same meaning.

## Shared Options

| Option                     | Meaning                                                                                                                         |
| -------------------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| `--archive-format`         | Force a format. The file signature must still match, unless `--force` is set.                                                   |
| `--json` / `--jsonl`       | Machine-readable output. Diagnostics stay on standard error.                                                                    |
| `--output`                 | Write the report to a file. `cat` does not use this. `get` uses it as the output file when one member is selected.              |
| `--nested` / `--recursive` | Walk archives stored inside the archive.                                                                                        |
| `--max-depth`              | Nested-archive depth. This is not `tree --depth`.                                                                               |
| `--max-size`               | Maximum decompressed bytes for one member. On `find`, this is the search filter; use `--max-member-size` there for the ceiling. |
| `--max-member-size`        | Same ceiling as `--max-size`, on every command including `find`.                                                                |
| `--timeout`                | Stop when the time limit is reached.                                                                                            |
| `--verbose` / `--quiet`    | More limitations, or no warnings.                                                                                               |
| `--no-colour`              | Plain text.                                                                                                                     |
| `--config`                 | TOML file. Overrides the user file.                                                                                             |
| `--password-file`          | Read the password from the first line of a file.                                                                                |
| `--password-stdin`         | Read the password from standard input.                                                                                          |
| `--force`                  | Allow a signature mismatch, and allow `cat` of binary data on a terminal.                                                       |

A size may be a plain byte count or a number with a unit: `B`, `KiB`, `MiB`, `GiB`, `KB`, `MB`, or
`GB`.

## Inspect

```bash
archive-explorer inspect backup.tar.gz
archive-explorer inspect package.zip --json
archive-explorer inspect collection.7z --detailed
archive-explorer inspect backup.zip --member projects/source.tar.gz
```

`inspect` prints the archive name, detected format, compressed size, declared uncompressed size,
file and directory counts, date range, encryption, nested-archive count, compression saving,
backend, and limitations. `--detailed` adds compression methods, comments, duplicate paths, and
unusual traits the backend could see. `--member` inspects one nested archive instead of the outer
file.

Declared sizes are taken from the archive. They can be wrong. A format that does not store a per-
member compressed size reports that size as unavailable.

## List

```bash
archive-explorer list backup.zip
archive-explorer list backup.zip --path Documents/
archive-explorer list backup.zip --sort size --descending --long
```

`--sort` accepts `name`, `size`, `date`, `type`, and `ratio`. `--type` accepts `file`, `directory`,
`symlink`, `hardlink`, and `other`. `--limit` and `--offset` page the listing. `--long` includes
type, sizes, time, permissions, and compression method. Missing metadata is the word `unavailable`.

Duplicate paths are kept as separate members. A path that occurs twice is shown with `@@2` on the
second occurrence. Commands that need one member refuse an ambiguous path instead of picking the
first or the last.

## Tree

```bash
archive-explorer tree backup.zip
archive-explorer tree backup.zip --depth 3 --sizes
archive-explorer tree backup.zip --path Projects/ --directories-only
```

The tree is built from member paths. It does not write the archive to disk. `--depth` is directory
depth. Nested archives that were recognised are marked with their format. Implicit directories are
created when members live under a folder the archive never stored as its own entry. In JSON, those
nodes have `"inferred": true`.

## Find

```bash
archive-explorer find backup.zip "*.conf"
archive-explorer find backup.zip --min-size 100MB --type file
archive-explorer find backup.zip --modified-after 2025-01-01
archive-explorer find backup.zip "*.json" --nested
```

The optional pattern matches the file name, unless it contains a slash or you pass `--full-path`.
`--regex` uses a regular expression. `--ignore-case` folds case. `--max-size` and `--min-size`
filter on uncompressed size. `--match all` (the default) requires every filter. `--match any` keeps
a member that satisfies one filter. `--fail-on-empty` exits 1 when nothing matches. With no matches
and without that flag, the exit code is 0.

Virtual directories that were not stored as members are included, so `--type directory` can see
them. They are marked inferred in JSON.

## Grep

```bash
archive-explorer grep backup.zip "database_url"
archive-explorer grep backup.zip "TODO" --include "*.py"
archive-explorer grep backup.zip "password" --ignore-case --nested
```

The default search is a literal string. `--regex` compiles a pattern. `--include` and `--exclude`
are file-name globs. `--encoding` overrides the default. `--encoding-errors` is `strict`, `replace`,
or `ignore`. `--context` adds lines around a hit. `--count` prints counts. `--files-with-matches`
prints paths only. Likely binary members are skipped unless `--binary` is set. Binary mode still
decodes bytes with the selected error policy; it is not a raw byte search.

Control characters other than tab and newline are escaped as `\xNN` so a member cannot rewrite the
terminal.

A member is read in chunks, and the decompressed-byte budget still applies. Very long lines are
truncated to the configured line length.

## Cat

```bash
archive-explorer cat backup.zip --path config/settings.toml
archive-explorer cat backup.zip --path config/settings.toml | grep database
```

Standard output is the member's bytes. There is no banner, no added newline, and no text decoding. A
failure is reported on standard error and the exit code is non-zero. A broken pipe exits 0.

Binary output to a terminal requires `--force`. A pipe or a redirect does not.

Select a member with `--path`, `--index` (1-based), or `--selector`. `--selector` is a JSON object
or a list of objects, each with `path` or `index`, and an optional `occurrence`. Use one selection
style at a time.

Symbolic links are not followed. `--follow-symlinks` follows them inside the same archive, stops on
a cycle, and refuses an absolute target or a `..` segment.

## Get

```bash
archive-explorer get backup.zip --path config/settings.toml --output settings.toml
archive-explorer get backup.zip --glob "*.conf" --dest ./out
archive-explorer get outer.zip \
    --path "projects/source.tar.gz::config/settings.toml" \
    --output settings.toml
```

One member plus `--output` writes that file. Several members need `--dest`. `--flatten` uses only
the file name. `--dry-run` prints the planned paths and writes nothing.

The destination is a directory you chose. Member paths cannot be absolute, cannot contain `..`, and
cannot use a Windows reserved name. The default policy writes regular files and directories.
Symbolic links need `--allow-symlinks`. Hard links need `--allow-hardlinks` and must point at a file
already extracted inside the destination. Device files and other special members are refused.

Each file is written to a temporary name in the destination directory, then renamed into place. A
partial file is not reported as success. An existing destination file is left unchanged unless
`--force` is set.

## Diff

```bash
archive-explorer diff old.zip new.zip
archive-explorer diff old.zip new.zip --mode content
archive-explorer diff old.zip new.zip --mode detailed
```

`fast` compares paths, types, declared sizes, timestamps, and stored checksums. It does not claim
that equal names and sizes mean equal contents. `content` hashes regular files with SHA-256.
`detailed` does that and adds a unified diff for text files up to the configured diff size. Binary
files are not passed through the text diff. `--ignore-whitespace` collapses whitespace before that
diff.

Members are paired by normalised path and occurrence. `--ignore-case-paths` is the only case-folding
mode. Distinct entries are not merged.

## Duplicates

```bash
archive-explorer duplicates backup.zip
archive-explorer duplicates backup.zip --nested
archive-explorer duplicates backup-a.zip backup-b.zip
```

Candidates are grouped by declared size, then by SHA-256. A group lists the paths, the content size,
the hash, the number of copies, and the redundant uncompressed bytes. Estimated archive storage
savings are `null` unless a format exposes a reliable per-member compressed size, which these
backends do not claim.

## Nested

```bash
archive-explorer nested backup.zip
archive-explorer nested backup.zip --depth 3
```

This lists archives found inside the archive, with their virtual paths and detected formats. A
corrupt nested archive is reported on its own and does not hide the rest of the scan. Other commands
accept the same archives through `--nested` or a `::` path.

## Safety

```bash
archive-explorer safety download.zip
archive-explorer safety backup.tar.gz --nested --json
```

The scan reports path traversal, absolute and Windows paths, links, special files, duplicate and
colliding names, reserved names, odd compression ratios, encrypted members, and bomb indicators. A
finished scan exits 0 even when findings exist. Exit code 4 is reserved for an extraction that the
safety policy refused.

Each finding has a stable id, a severity, the member, an explanation, a consequence, a recommended
action, and the detection limit. The text report states that this is not antivirus and does not
prove the archive is safe.

## Test

```bash
archive-explorer test backup.zip
archive-explorer test backup.tar.gz --full
archive-explorer test collection.7z --nested
```

Structural mode checks that members can be listed. Full mode decompresses regular files and checks a
stored CRC or checksum when the backend has one. An archive with no stored checksums can still pass
decompression, and the report says what was not verified. A passed test is not a statement of
cryptographic authenticity.

Outcomes are `passed`, `failed`, `incomplete`, and `unsupported`.

## Report

```bash
archive-explorer report backup.zip --format html --output archive-report.html
archive-explorer report backup.zip --format markdown
archive-explorer report backup.zip --format json
```

`--format` here is `text`, `json`, `jsonl`, `markdown`, or `html`. It is not the archive format;
that option is `--archive-format`. HTML is one self-contained file, with filenames escaped, and it
does not need a web server. `--full` includes an integrity pass. Reports can include the summary,
large files and directories, nested archives, duplicate groups, safety findings, and backend
limitations.

## Formats and Version

```bash
archive-explorer formats
archive-explorer formats --json
archive-explorer version
archive-explorer --version
```

`formats` reports the backends that imported successfully in this process, including detection,
listing, streaming, extraction, integrity, encryption, nested access, and known limitations.
