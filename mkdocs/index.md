# Archive Explorer

Archive Explorer is an offline command-line tool for reading compressed archives without unpacking
them. It treats an archive as a virtual filesystem: you can list it, search it, stream one member,
and open an archive that is stored inside another archive.

Read-only commands do not modify the source file. Inspection never extracts the whole archive as a
hidden workaround. A member is decompressed only when a command needs its bytes.

## What You Can Do

- Inspect size, dates, compression, and member counts.
- List members and show a virtual directory tree.
- Search by name, path, size, type, and date.
- Search text inside members.
- Stream one member to standard output.
- Extract a selection into a destination you choose.
- Compare two archives and find duplicate contents.
- Walk nested archives, assess extraction risks, and test integrity.
- Write text, JSON, JSON Lines, Markdown, and HTML reports.

The tool is not an archive creator, a malware scanner, or a sandbox. A clean safety report does not
prove an archive is safe to open elsewhere.

## Four Different Operations

These are not the same action:

| Operation                    | What happens                                                            |
| ---------------------------- | ----------------------------------------------------------------------- |
| Listing                      | Reads archive metadata and prints paths. Member bytes stay compressed.  |
| Decompressing a member       | Reads one member, for `cat`, `grep`, hashing, or a full integrity test. |
| Extracting a member          | Writes that member under a destination directory, after path checks.    |
| Extracting an entire archive | Not what this tool does. Select the members you want.                   |

Some formats can jump to one member. A compressed tar, a solid 7z archive, and a single-stream gzip
file may have to be read from the start before the requested bytes are available. Archive Explorer
reports that limitation instead of pretending every format is random-access.
