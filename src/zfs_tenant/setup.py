"""Create a tenant root, lock down its properties, and delegate it, idempotently."""

from __future__ import annotations

import pwd
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, NoReturn

from zfs_tenant import names, zfs

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
_BANNER = re.compile(r"-{4} Permissions on (\S+) -{4,}")
_RIGHTS = re.compile(r"[a-zA-Z0-9_:@.-]+(?:,[a-zA-Z0-9_:@.-]+)*")
_SECTIONS = {
    "Permission sets:",
    "Create time permissions:",
    "Local permissions:",
    "Descendent permissions:",
    "Local+Descendent permissions:",
}
_LOCAL = set(LOCAL_PERMISSIONS.split(","))
_DESCENDANT = set(DESCENDANT_PERMISSIONS.split(","))


class SetupError(RuntimeError):
    """The tenant cannot be set up as requested."""


def _reject(message: str) -> NoReturn:
    raise SetupError(message)


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


def commands(spec: TenantSpec, *, keep_mountpoint: bool = False) -> list[list[str]]:
    """Return the zfs argument lists that bring the tenant root to the desired state.

    With *keep_mountpoint*, leave out ``mountpoint=none``: once zoned children inherit it,
    OpenZFS rejects even a write that changes nothing.
    """
    properties = [
        f"quota={spec.quota}",
        f"reservation={spec.reservation or 'none'}",
        f"filesystem_limit={spec.filesystem_limit}",
        f"snapshot_limit={spec.snapshot_limit}",
        *(p for p in FIXED_PROPERTIES if not (keep_mountpoint and p == "mountpoint=none")),
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
    try:
        identity = pwd.getpwnam(spec.user)
    except KeyError as error:
        msg = f"user {spec.user!r} does not exist"
        raise SetupError(msg) from error
    identities = {identity.pw_name, str(identity.pw_uid)}
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
    parent = spec.root.rsplit("/", 1)[0]
    while not _exists(parent, zfs_path, runner):
        if "/" not in parent:
            _reject(f"no existing parent for {spec.root}")
        parent = parent.rsplit("/", 1)[0]
    zoned = runner([zfs_path, "get", "-H", "-o", "value", "zoned", parent]).strip()
    if zoned != "off":
        _reject(f"parent {parent} must have zoned=off, got {zoned!r}")

    exists = _exists(spec.root, zfs_path, runner)
    if exists:
        _audit_tree(spec.root, identities, zfs_path, runner)
    keep_mountpoint = exists and _mountpoint_is_local_none(spec, zfs_path, runner)
    for args in commands(spec, keep_mountpoint=keep_mountpoint):
        runner([zfs_path, *args])
        if args[0] == "create" and not exists:
            # Parent create-time permissions can appear on the newly created root.
            _audit_tree(spec.root, identities, zfs_path, runner)
    local, descendant = _audit_tree(spec.root, identities, zfs_path, runner)
    if local != _LOCAL or descendant != _DESCENDANT:
        _reject("final delegation does not match the intended grants")


def _exists(dataset: str, zfs_path: str, runner: Runner) -> bool:
    try:
        runner([zfs_path, "list", "-H", "-o", "name", dataset])
    except zfs.CommandError as error:
        if zfs.does_not_exist(error):
            return False
        raise
    return True


def _valid_entry(section: str, line: str) -> bool:
    parts = line.split()
    if section == "Permission sets:":
        valid = len(parts) == 2 and parts[0].startswith("@")  # noqa: PLR2004
    elif section == "Create time permissions:":
        valid = len(parts) == 1
    else:
        valid = (len(parts) == 3 and parts[0] in {"user", "group"}) or (  # noqa: PLR2004
            len(parts) == 2 and parts[0] == "everyone"  # noqa: PLR2004
        )
    return valid and _RIGHTS.fullmatch(parts[-1]) is not None


def _parse_allow(output: str) -> dict[str, list[tuple[str, str]]]:  # noqa: C901 - explicit output grammar
    """Read only the documented banner/section/entry form of zfs allow."""
    blocks: dict[str, list[tuple[str, str]]] = {}
    source = section = None
    pending = False
    seen_sections: set[str] = set()
    for raw in output.splitlines():
        line = raw.strip()
        if not line:
            continue
        if match := _BANNER.fullmatch(line):
            if pending:
                _reject(f"empty delegation section {section}")
            source = match[1]
            if not names.is_dataset(source) or source in blocks:
                _reject(f"invalid or duplicate delegation source {source!r}")
            blocks[source] = []
            section = None
            seen_sections.clear()
        elif line in _SECTIONS and source is not None:
            if pending or line in seen_sections:
                _reject(f"empty or repeated delegation section {line}")
            section = line
            seen_sections.add(line)
            pending = True
        elif source is not None and section is not None:
            if not _valid_entry(section, line):
                _reject(f"malformed delegation entry {line!r}")
            blocks[source].append((section, line))
            pending = False
        else:
            _reject(f"unknown delegation output {line!r}")
    if pending or any(not entries for entries in blocks.values()):
        _reject("empty delegation source block")
    return blocks


def _root_rights(
    entries: list[tuple[str, str]], identities: set[str], root: str
) -> tuple[set[str], set[str]]:
    local: set[str] = set()
    descendant: set[str] = set()
    for section, entry in entries:
        parts = entry.split()
        if section in {"Permission sets:", "Create time permissions:"}:
            _reject(f"unexpected {section} on {root}")
        if parts[0] != "user" or parts[1] not in identities:
            _reject(f"unexpected delegation {entry!r} on {root}")
        rights = set(parts[2].split(","))
        allowed = _LOCAL if section == "Local permissions:" else _DESCENDANT
        if section == "Local+Descendent permissions:":
            allowed = _LOCAL & _DESCENDANT
        if not rights <= allowed:
            _reject(f"unexpected delegation rights {parts[2]!r} on {root}")
        if section != "Descendent permissions:":
            local.update(rights)
        if section != "Local permissions:":
            descendant.update(rights)
    return local, descendant


def _audit_tree(
    root: str, identities: set[str], zfs_path: str, runner: Runner
) -> tuple[set[str], set[str]]:
    listed = runner([zfs_path, "list", "-H", "-r", "-t", "filesystem,volume", "-o", "name", root])
    datasets = listed.splitlines()
    if root not in datasets or any(d != root and not d.startswith(root + "/") for d in datasets):
        _reject("unexpected dataset listing for tenant root")
    local: set[str] = set()
    descendant: set[str] = set()
    seen: set[str] = set()
    for dataset in datasets:
        for source, entries in _parse_allow(runner([zfs_path, "allow", dataset])).items():
            if source != dataset and not dataset.startswith(source + "/"):
                _reject(f"delegation source {source!r} is not an ancestor of {dataset!r}")
            if source in seen:
                continue
            seen.add(source)
            if source != root and not source.startswith(root + "/"):
                # The caller verified an unzoned parent boundary before this audit.
                continue
            if source != root:
                _reject(f"unexpected delegation on child {source}")
            root_local, root_descendant = _root_rights(entries, identities, root)
            local.update(root_local)
            descendant.update(root_descendant)
    return local, descendant


def _mountpoint_is_local_none(spec: TenantSpec, zfs_path: str, runner: Runner) -> bool:
    # Only a local value counts: an inherited one would follow a later change to an ancestor.
    try:
        output = runner([zfs_path, "get", "-H", "-o", "value,source", "mountpoint", spec.root])
    except zfs.CommandError as error:
        if zfs.does_not_exist(error):
            return False
        raise
    return output.strip() == "none\tlocal"
