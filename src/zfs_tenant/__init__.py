"""Give a friend a quota-capped corner of your ZFS pool for raw encrypted backups."""

from __future__ import annotations

try:
    from zfs_tenant._version import __version__
except ImportError:  # pragma: no cover - source tree without a build
    __version__ = "0.0.0"

__all__ = ["__version__"]
