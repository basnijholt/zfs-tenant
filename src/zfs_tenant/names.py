"""Validate OpenZFS names and keep them inside a tenant root."""

from __future__ import annotations

import re

_COMPONENT = re.compile(r"[A-Za-z0-9_.:-]+")
_SNAPSHOT = re.compile(r"[A-Za-z0-9_.:-]+")


def is_dataset(name: str) -> bool:
    """Return whether *name* is a filesystem or volume name this package accepts."""
    return all(
        _COMPONENT.fullmatch(part) is not None
        and part not in {".", ".."}
        and not part.startswith("-")
        for part in name.split("/")
    )


def is_snapshot_name(name: str) -> bool:
    """Return whether *name* is an acceptable snapshot name (the part after ``@``)."""
    return _SNAPSHOT.fullmatch(name) is not None and not name.startswith("-")


def in_scope(root: str, name: str) -> bool:
    """Return whether dataset *name* is *root* or one of its descendants."""
    return is_dataset(name) and (name == root or name.startswith(root + "/"))


def strictly_below(root: str, name: str) -> bool:
    """Return whether dataset *name* is a descendant of *root*, excluding *root* itself."""
    return name != root and in_scope(root, name)


def split_snapshot(full_name: str) -> tuple[str, str] | None:
    """Split ``dataset@snapshot`` into its parts, or return None if it is not one."""
    dataset, separator, snapshot = full_name.partition("@")
    if not separator or not is_dataset(dataset) or not is_snapshot_name(snapshot):
        return None
    return dataset, snapshot


def pool_of(name: str) -> str:
    """Return the pool component of a dataset name."""
    return name.split("/", 1)[0]
