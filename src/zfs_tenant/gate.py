"""Execute one allowed request as the tenant user."""

from __future__ import annotations

import re
import subprocess
import sys
import syslog
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Protocol

from zfs_tenant import grammar, names, zfs

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

_DENIED_STATUS = 126
_TONAME = re.compile(r"^\s*toname = (\S+)\s*$", re.MULTILINE)


@dataclass(frozen=True)
class GateConfig:
    """The tenant root and the binaries the gate may run."""

    root: str
    zfs: str = "zfs"
    zpool: str = "zpool"
    require_encryption: bool = True


class _Spawner(Protocol):
    """Run a command attached to the SSH session and return its exit status."""

    def __call__(self, argv: Sequence[str], *, merge_stderr: bool) -> int:
        """Run *argv*; with *merge_stderr*, send its stderr to stdout."""


def _spawn(argv: Sequence[str], *, merge_stderr: bool) -> int:
    """Run *argv* with the session's stdin and stdout and return its exit status."""
    stderr = subprocess.STDOUT if merge_stderr else None
    return subprocess.run(list(argv), stderr=stderr, check=False).returncode  # noqa: S603 - argv comes from grammar.parse


def log_to_syslog(message: str) -> None:
    """Record one gate decision in the auth log."""
    syslog.openlog("zfs-tenant", syslog.LOG_PID, syslog.LOG_AUTH)
    syslog.syslog(syslog.LOG_INFO, message)


def _write_stderr(message: str) -> None:
    """Print *message* for the SSH client."""
    sys.stderr.write(message + "\n")


@dataclass(frozen=True)
class _Effects:
    """Side effects the gate needs; tests replace them."""

    runner: zfs.Runner = zfs.run
    spawner: _Spawner = _spawn
    log: Callable[[str], None] = log_to_syslog
    write_error: Callable[[str], None] = field(default=_write_stderr)


def handle(command: str | None, config: GateConfig, effects: _Effects | None = None) -> int:
    """Parse and execute *command*, returning the exit status for the SSH session."""
    fx = effects or _Effects()
    if command is None:
        fx.log(f"root={config.root} denied interactive session")
        fx.write_error("zfs-tenant: interactive sessions are not allowed")
        return _DENIED_STATUS
    request = grammar.parse(command, config.root)
    if isinstance(request, grammar.Rejected):
        fx.log(f"root={config.root} denied {command!r}: {request.reason}")
        fx.write_error(f"zfs-tenant: command not allowed: {request.reason}")
        return _DENIED_STATUS
    fx.log(f"root={config.root} allowed {command!r}")
    try:
        return _execute(request, config, fx)
    except zfs.CommandError as error:
        fx.write_error(f"zfs-tenant: {error}")
        return 1


def _execute(request: grammar.Request, config: GateConfig, fx: _Effects) -> int:
    if isinstance(request, grammar.Reply):
        return request.status
    if isinstance(request, grammar.Run):
        binary = config.zfs if request.program == "zfs" else config.zpool
        return fx.spawner([binary, *request.args], merge_stderr=False)
    if isinstance(request, grammar.ResumeSend):
        return _resume_send(request.token, config, fx)
    return _receive(request, config, fx)


def _resume_send(token: str, config: GateConfig, fx: _Effects) -> int:
    described = fx.runner([config.zfs, "send", "-nvP", "-t", token])
    match = _TONAME.search(described)
    parts = names.split_snapshot(match.group(1)) if match else None
    if parts is None or not names.in_scope(config.root, parts[0]):
        fx.write_error("zfs-tenant: resume token does not name a snapshot inside the tenant root")
        return _DENIED_STATUS
    return fx.spawner([config.zfs, "send", "-t", token], merge_stderr=False)


def _receive(request: grammar.Receive, config: GateConfig, fx: _Effects) -> int:
    before: dict[str, str] = {}
    if config.require_encryption:
        before = _encryption(request.dataset, config, fx)
        if before.get(request.dataset) == "off":
            fx.write_error(
                f"zfs-tenant: {request.dataset} is unencrypted; "
                "this host only accepts raw encrypted sends (zfs send -w)"
            )
            return 1
    argv = [config.zfs, "receive", "-u"]
    if request.resumable:
        argv.append("-s")
    if request.force:
        argv.append("-F")
    argv.append(request.dataset)
    status = fx.spawner(argv, merge_stderr=True)
    if status != 0 or not config.require_encryption:
        return status
    after = _encryption(request.dataset, config, fx)
    # New datasets, and any a forced receive turned unencrypted; pre-existing plaintext stays.
    plain = sorted(
        name
        for name, encryption in after.items()
        if encryption == "off" and before.get(name) != "off"
    )
    if not plain:
        return 0
    for name in _topmost(plain):
        fx.runner([config.zfs, "destroy", "-r", name])
        fx.write_error(f"zfs-tenant: refused unencrypted dataset {name}; send raw (zfs send -w)")
    return 1


def _encryption(dataset: str, config: GateConfig, fx: _Effects) -> dict[str, str]:
    argv = [config.zfs, "list", "-H", "-r", "-t", "filesystem,volume", "-o", "name,encryption"]
    try:
        output = fx.runner([*argv, dataset])
    except zfs.CommandError as error:
        if zfs.does_not_exist(error):
            return {}
        raise
    encryption: dict[str, str] = {}
    for line in output.splitlines():
        name, _, value = line.partition("\t")
        if name:
            encryption[name] = value
    return encryption


def _topmost(datasets: list[str]) -> list[str]:
    return [
        name for name in datasets if not any(name.startswith(other + "/") for other in datasets)
    ]
