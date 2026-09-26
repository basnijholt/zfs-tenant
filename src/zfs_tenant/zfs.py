"""Run zfs and zpool with captured output."""

from __future__ import annotations

import subprocess
from collections.abc import Callable, Sequence

Runner = Callable[[Sequence[str]], str]


class CommandError(RuntimeError):
    """A command exited with a non-zero status."""

    def __init__(self, argv: Sequence[str], status: int, stderr: str) -> None:
        """Remember the failed command, its status, and its stderr."""
        self.argv = tuple(argv)
        self.status = status
        self.stderr = stderr
        super().__init__(f"{' '.join(self.argv)} exited {status}: {stderr.strip()}")


def run(argv: Sequence[str]) -> str:
    """Run *argv* without a shell and return stdout; raise CommandError on failure."""
    result = subprocess.run(list(argv), capture_output=True, text=True, check=False)  # noqa: S603 - argv is built by this package
    if result.returncode != 0:
        raise CommandError(argv, result.returncode, result.stderr)
    return result.stdout


def does_not_exist(error: CommandError) -> bool:
    """Return whether *error* is zfs reporting a missing dataset."""
    return "does not exist" in error.stderr
