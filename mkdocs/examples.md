# Examples

## Inspect a Download

```bash
archive-explorer inspect download.zip
archive-explorer tree download.zip --depth 3
archive-explorer safety download.zip
```

Read the warnings before you extract anything with another tool. Absolute paths and `..` segments
are findings even when you only looked.

## Find Configuration in a Backup

```bash
archive-explorer find backup.tar.gz "*.conf"
archive-explorer grep backup.tar.gz "database_url"
```

`find` matches names. `grep` reads member text. Add `--nested` when the setting file may sit inside
an archive that is itself stored in the backup.

## Read One File

```bash
archive-explorer cat backup.zip --path config/settings.toml
```

The bytes on standard output are the decompressed member. Nothing is written next to the archive.

## Pipe a Virtual File

```bash
archive-explorer cat backup.zip \
    --path config/settings.toml | grep database
```

`grep` in that pipeline is the system grep. It sees only the one file `cat` streamed.

## Open a Nested Member

```bash
archive-explorer cat outer.zip \
    --path "projects/source.tar.gz::config/settings.toml"
```

The outer ZIP is opened, the tar member is recognised, and `config/settings.toml` is streamed. If
the tar member has to be copied to temporary storage, that note goes to standard error, not into the
file bytes.

## Extract One Nested File

```bash
archive-explorer get outer.zip \
    --path "projects/source.tar.gz::config/settings.toml" \
    --output settings.toml
```

`settings.toml` is created in the current directory. The archives are unchanged.

## Compare Two Backups

```bash
archive-explorer diff backup-old.tar.gz backup-new.tar.gz --mode content
```

Content mode hashes file bytes. Fast mode, the default, only compares metadata and will say so.

## Find Duplicate Content

```bash
archive-explorer duplicates backup.zip --nested
```

Groups are exact SHA-256 matches. The redundant-byte figure is uncompressed size, not the space you
would gain by rewriting the archive.

## Test Integrity

```bash
archive-explorer test backup.zip --full
```

A failure exits 3 and names the member on standard error and in `--json` output.

## Write a Report

```bash
archive-explorer report backup.zip \
    --format html \
    --output archive-report.html
```

Open the HTML file locally. It does not phone home, and it does not need MkDocs or a browser server.
