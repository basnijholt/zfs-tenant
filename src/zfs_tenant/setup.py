"""Create a tenant root, lock down its properties, and delegate it, idempotently."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING

from zfs_tenant import names

if TYPE_CHECKING:
    from zfs_tenant.zfs import Runner

FIXED_PROPERTIES = (
    "mountpoint=none",
    "canmount=off",
    "readonly=on",
    "exec=off",
    "setuid=off",
    "devices=off",
    "volmode=none",
    # Zoned datasets are never mounted on the host, so they are never shared either;
    # OpenZFS also refuses to set sharenfs/sharesmb once zoned=on.
    "zoned=on",
)
LOCAL_PERMISSIONS = "create,mount,receive"
DESCENDANT_PERMISSIONS = "create,destroy,mount,receive,send"

_SIZE = re.compile(r"[0-9]+(?:\.[0-9]+)?[KMGTPE]?")
_USER = re.compile(r"[a-z_][a-z0-9_-]{0,31}")


class SetupError(RuntimeError):
    """The tenant cannot be set up as requested."""


@dataclass(frozen=True)
class TenantSpec:
    """One tenant root and the limits it gets."""

    root: str
    user: str
    quota: str
    reservation: str | None = None
    filesystem_limit: int = 100
    snapshot_limit: int = 20000


def validate(spec: TenantSpec) -> None:
    """Raise SetupError unless *spec* is safe to turn into zfs commands."""
    if not names.is_dataset(spec.root) or "/" not in spec.root:
        msg = f"root must be a dataset below a pool, got {spec.root!r}"
        raise SetupError(msg)
    if _USER.fullmatch(spec.user) is None:
        msg = f"invalid user name {spec.user!r}"
        raise SetupError(msg)
    for label, size in (("quota", spec.quota), ("reservation", spec.reservation)):
        if size is not None and _SIZE.fullmatch(size) is None:
            msg = f"invalid {label} {size!r}; use a size such as 500G or 2T"
            raise SetupError(msg)
    if spec.filesystem_limit < 1 or spec.snapshot_limit < 1:
        msg = "filesystem and snapshot limits must be positive"
        raise SetupError(msg)


def commands(spec: TenantSpec) -> list[list[str]]:
    """Return the zfs argument lists that bring the tenant root to the desired state."""
    properties = [
        f"quota={spec.quota}",
        f"reservation={spec.reservation or 'none'}",
        f"filesystem_limit={spec.filesystem_limit}",
        f"snapshot_limit={spec.snapshot_limit}",
        *FIXED_PROPERTIES,
    ]
    return [
        ["create", "-p", spec.root],
        ["set", *properties, spec.root],
        ["unallow", "-u", spec.user, spec.root],
        ["allow", "-l", "-u", spec.user, LOCAL_PERMISSIONS, spec.root],
        ["allow", "-d", "-u", spec.user, DESCENDANT_PERMISSIONS, spec.root],
    ]


def apply(spec: TenantSpec, *, zfs_path: str, zpool_path: str, runner: Runner) -> None:
    """Validate *spec*, check the pool supports limits, and run every setup command."""
    validate(spec)
    pool = names.pool_of(spec.root)
    feature = runner(
        [zpool_path, "get", "-H", "-o", "value", "feature@filesystem_limits", pool]
    ).strip()
    if feature not in {"enabled", "active"}:
        msg = (
            f"pool {pool} has feature@filesystem_limits={feature or 'unknown'}; "
            f"enable it with: zpool set feature@filesystem_limits=enabled {pool}"
        )
        raise SetupError(msg)
    for args in commands(spec):
        runner([zfs_path, *args])
