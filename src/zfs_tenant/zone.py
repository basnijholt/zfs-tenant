"""Keep a tenant's user namespace alive and attach the tenant root to it with ``zfs zone``.

Inside that namespace the ZFS kernel module hides every dataset that is not attached,
so the host's other datasets stay invisible even if the gate had a bug. The tenant keeps
its own uid inside the namespace, so ``zfs`` runs there without capabilities and
``zfs allow`` still decides what the tenant may change.

``serve`` runs as root: it forks a holder process that drops to the tenant user, creates
the namespace, and then only sleeps. The root parent attaches the tenant root to that
namespace, writes the holder's pid for the gate, and detaches again when it stops.
``enter`` is what the gate calls to join the namespace before it runs anything; it then
drops the capabilities that joining a user namespace grants.
"""

from __future__ import annotations

import contextlib
import ctypes
import os
import pwd
import signal
import sys
from pathlib import Path
from typing import TYPE_CHECKING, NoReturn

from zfs_tenant import zfs

if TYPE_CHECKING:
    from collections.abc import Callable

CLONE_NEWUSER = 0x10000000
_PR_SET_DUMPABLE = 4
_CAPABILITY_VERSION_3 = 0x20080522
_STOP_SIGNALS = {signal.SIGTERM, signal.SIGINT}


class ZoneError(RuntimeError):
    """The tenant namespace cannot be created, attached, or entered."""


def _libc(name: str, *args: int) -> None:
    function = getattr(ctypes.CDLL(None, use_errno=True), name)
    if function(*args) != 0:
        errno = ctypes.get_errno()
        raise OSError(errno, os.strerror(errno))


def _syscall(name: str, *args: int) -> None:
    """Call ``os.<name>`` (Python 3.12+) or the libc function of the same name."""
    function: Callable[..., None] | None = getattr(os, name, None)
    if function is not None:
        function(*args)
    else:
        _libc(name, *args)


class _CapHeader(ctypes.Structure):
    _fields_ = (("version", ctypes.c_uint32), ("pid", ctypes.c_int))


class _CapData(ctypes.Structure):
    _fields_ = (
        ("effective", ctypes.c_uint32),
        ("permitted", ctypes.c_uint32),
        ("inheritable", ctypes.c_uint32),
    )


def _drop_capabilities() -> None:
    """Clear this process's capability sets and verify none are left."""
    header = _CapHeader(_CAPABILITY_VERSION_3, 0)
    data = (_CapData * 2)()
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.capset(ctypes.byref(header), data) != 0:
        errno = ctypes.get_errno()
        raise OSError(errno, os.strerror(errno))
    status = Path("/proc/self/status").read_text()
    effective = next(line for line in status.splitlines() if line.startswith("CapEff:"))
    if int(effective.split()[1], 16) != 0:
        msg = f"capabilities are still set after joining the tenant namespace: {effective}"
        raise ZoneError(msg)


def _namespace_inode(pid: int | str) -> int:
    return Path(f"/proc/{pid}/ns/user").stat().st_ino


def enter(pid_file: Path) -> None:
    """Join the user namespace of the holder whose pid is in *pid_file*."""
    try:
        pid = int(pid_file.read_text().strip())
    except (OSError, ValueError) as error:
        msg = f"the tenant namespace is not running ({pid_file}: {error})"
        raise ZoneError(msg) from error
    before = _namespace_inode("self")
    try:
        fd = os.open(f"/proc/{pid}/ns/user", os.O_RDONLY)
    except OSError as error:
        msg = f"the tenant namespace is not running (pid {pid}: {error.strerror})"
        raise ZoneError(msg) from error
    try:
        _syscall("setns", fd, CLONE_NEWUSER)
    except OSError as error:
        msg = f"cannot join the tenant namespace: {error.strerror}"
        raise ZoneError(msg) from error
    finally:
        os.close(fd)
    if _namespace_inode("self") == before:
        msg = "the pid file does not point at a separate user namespace"
        raise ZoneError(msg)
    # Joining a user namespace grants every capability inside it, and ZFS treats
    # CAP_SYS_ADMIN there as zone administration, which bypasses `zfs allow`.
    try:
        _drop_capabilities()
    except OSError as error:
        msg = f"cannot drop capabilities in the tenant namespace: {error.strerror}"
        raise ZoneError(msg) from error


def _hold(uid: int, gid: int, ready: int) -> NoReturn:
    """Become the tenant, create a user namespace mapping it to itself, and sleep."""
    try:
        signal.pthread_sigmask(signal.SIG_SETMASK, set())
        os.setgroups([])
        os.setgid(gid)
        os.setuid(uid)
        # Changing uid makes a process non-dumpable, which would hide /proc/<pid>/ns
        # from the tenant's own gate processes.
        _libc("prctl", _PR_SET_DUMPABLE, 1, 0, 0, 0)
        _syscall("unshare", CLONE_NEWUSER)
        Path("/proc/self/setgroups").write_text("deny")
        Path("/proc/self/uid_map").write_text(f"{uid} {uid} 1\n")
        Path("/proc/self/gid_map").write_text(f"{gid} {gid} 1\n")
        os.write(ready, b"1")
    except OSError:
        os._exit(1)
    os.close(ready)
    while True:
        signal.pause()


def _spawn_holder(user: str) -> int:
    account = pwd.getpwnam(user)
    if account.pw_uid == 0:
        msg = "the tenant user must not be root"
        raise ZoneError(msg)
    read_end, write_end = os.pipe()
    child = os.fork()
    if child == 0:
        os.close(read_end)
        _hold(account.pw_uid, account.pw_gid, write_end)
    os.close(write_end)
    ready = os.read(read_end, 1)
    os.close(read_end)
    if ready != b"1":
        os.waitpid(child, 0)
        msg = f"the holder could not create a user namespace as {user}"
        raise ZoneError(msg)
    if _namespace_inode(child) == _namespace_inode("self"):
        msg = "the holder is still in the host's user namespace"
        raise ZoneError(msg)
    return child


def serve(root: str, user: str, pid_file: Path, *, zfs_path: str, runner: zfs.Runner) -> int:
    """Run the holder for *root* until SIGTERM or SIGINT; return 0 on a requested stop."""
    previous = signal.pthread_sigmask(signal.SIG_BLOCK, {*_STOP_SIGNALS, signal.SIGCHLD})
    try:
        return _serve(root, user, pid_file, zfs_path=zfs_path, runner=runner)
    finally:
        signal.pthread_sigmask(signal.SIG_SETMASK, previous)


def _serve(root: str, user: str, pid_file: Path, *, zfs_path: str, runner: zfs.Runner) -> int:
    child = _spawn_holder(user)
    # Keep the namespace open so it can be detached even after the holder dies.
    namespace = os.open(f"/proc/{child}/ns/user", os.O_RDONLY)
    namespace_path = f"/proc/{os.getpid()}/fd/{namespace}"
    try:
        runner([zfs_path, "zone", namespace_path, root])
        pid_file.parent.mkdir(parents=True, exist_ok=True)
        staging = pid_file.with_suffix(".tmp")
        staging.write_text(f"{child}\n")
        staging.chmod(0o644)
        staging.replace(pid_file)
        requested = _wait_for_stop_or_holder_exit(child)
    finally:
        pid_file.unlink(missing_ok=True)
        with contextlib.suppress(ProcessLookupError):
            os.kill(child, signal.SIGKILL)
        with contextlib.suppress(ChildProcessError):
            os.waitpid(child, 0)
        with contextlib.suppress(zfs.CommandError):
            runner([zfs_path, "unzone", namespace_path, root])
        os.close(namespace)
    return 0 if requested else 1


def _wait_for_stop_or_holder_exit(child: int) -> bool:
    """Return True on SIGTERM or SIGINT, False once the holder has exited."""
    while True:
        received = signal.sigwait({*_STOP_SIGNALS, signal.SIGCHLD})
        if received in _STOP_SIGNALS:
            return True
        # SIGCHLD also arrives for the zfs subprocesses this process runs.
        pid, _ = os.waitpid(child, os.WNOHANG)
        if pid == child:
            sys.stderr.write("zfs-tenant: the namespace holder exited\n")
            return False
