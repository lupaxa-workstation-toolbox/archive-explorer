"""Exit codes and errors for Archive Explorer."""

from __future__ import annotations


class ExitCode:
    """Process status codes.

    Search commands return 0 when nothing matches. ``--fail-on-empty`` uses
    code 1 for that case. Other failures keep the codes below, so a search
    miss stays distinct from corruption, policy refusals, and usage errors.
    """

    OK = 0
    FAILURE = 1
    USAGE = 2
    CORRUPT = 3
    SAFETY = 4
    UNSUPPORTED = 5
    PASSWORD = 6
    LIMIT = 7
    PARTIAL = 8
    NOT_FOUND = 9
    AMBIGUOUS = 10


class AppError(Exception):
    """An expected operational failure with a stable exit code."""

    def __init__(self, message: str, code: int = ExitCode.FAILURE) -> None:
        super().__init__(message)
        self.message = message
        self.code = code


class ConfigError(AppError):
    """Invalid configuration."""

    def __init__(self, message: str) -> None:
        super().__init__(message, ExitCode.USAGE)


def redact(message: str, secrets: list[str]) -> str:
    """Remove password material from a message."""
    redacted = message
    for secret in secrets:
        if secret:
            redacted = redacted.replace(secret, "******")
    return redacted
