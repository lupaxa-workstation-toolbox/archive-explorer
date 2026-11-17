"""Allow ``python -m lupaxa.archive_explorer``."""

from __future__ import annotations

import sys

from lupaxa.archive_explorer.cli import main

if __name__ == "__main__":
    sys.exit(main())
