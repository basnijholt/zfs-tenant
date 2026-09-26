"""Turn an SSH_ORIGINAL_COMMAND string into one allowed request, or reject it.

Pure functions only: no I/O and no ZFS calls. The gate executes what this returns,
always with an argv built here and never through a shell.
"""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal

from zfs_tenant import names

if TYPE_CHECKING:
    from collections.abc import Callable


@dataclass(frozen=True)
class Reply:
    """Answer a probe without running anything."""

    status: int


@dataclass(frozen=True)
class Run:
    """Run ``zfs`` or ``zpool`` with arguments the grammar built."""

    program: Literal["zfs", "zpool"]
    args: tuple[str, ...]


@dataclass(frozen=True)
class Receive:
    """Receive a stream from stdin into a dataset strictly below the root."""

    dataset: str
    resumable: bool
    force: bool


@dataclass(frozen=True)
class ResumeSend:
    """Resume an interrupted send; the gate checks which dataset the token names."""

    token: str


@dataclass(frozen=True)
class Rejected:
    """The command is not allowed; *reason* depends only on the input, so it is safe to show."""

    reason: str


Request = Reply | Run | Receive | ResumeSend

_PUNCTUATION = frozenset(";|&<>")
_REDIRECT = ["2", ">&", "1"]
_PROBED_COMMAND = re.compile(r"[a-z0-9]+")
_RESUME_TOKEN = re.compile(r"[0-9a-f]+(?:-[0-9a-f]+){3}")
_LIST_SWITCHES = re.compile(r"-[Hpr]+")
_SEND_SWITCHES = re.compile(r"-[wLceRp]+")
_DEPTH = re.compile(r"[0-9]{1,3}")
_LIST_TYPES = frozenset({"filesystem", "volume", "snapshot", "bookmark", "all"})
_LIST_COLUMNS = frozenset(
    {
        "name",
        "used",
        "available",
        "avail",
        "referenced",
        "refer",
        "logicalused",
        "creation",
        "type",
        "encryption",
        "keystatus",
        "encryptionroot",
        "userrefs",
        "defer_destroy",
        "quota",
        "filesystem_count",
        "snapshot_count",
        "filesystem_limit",
        "snapshot_limit",
        "receive_resume_token",
        "guid",
    }
)
_GET_FORMS = frozenset(
    {
        ("-H", "name"),
        ("-H", "receive_resume_token"),
        ("-H", "-p", "used"),
        ("-Hpd", "1", "-t", "snapshot", "guid,creation"),
        ("-Hpd", "1", "type,guid,creation"),
    }
)
_NO_ARGS_PROBES = (["exit"], ["echo", "-n"], ["ps", "-Ao", "args="])
_POOL_FEATURE_PROBE = ["zpool", "get", "-o", "value", "-H", "feature@extensible_dataset"]


def tokenize(command: str) -> list[str] | None:
    """Split *command* like a POSIX shell, keeping runs of ``;|&<>`` as separate tokens.

    Returns None for control characters or unbalanced quotes.
    """
    if any(ord(char) < 0x20 or ord(char) == 0x7F for char in command):  # noqa: PLR2004
        return None
    lexer = shlex.shlex(command, posix=True, punctuation_chars=";|&<>")
    lexer.whitespace_split = True
    lexer.commenters = ""
    try:
        return list(lexer)
    except ValueError:
        return None


def parse(command: str, root: str) -> Request | Rejected:
    """Return the single request *command* asks for, scoped to the tenant *root*."""
    tokens = tokenize(command)
    if not tokens:
        return Rejected("empty command, unbalanced quotes, or control characters")
    statements = _split_statements(tokens)
    if statements is None:
        return Rejected("shell syntax is not allowed")
    if len(statements) > 1:
        return _destroy_chain(statements, root)
    return _statement(statements[0], root)


def _split_statements(tokens: list[str]) -> list[list[str]] | None:
    statements: list[list[str]] = [[]]
    for word in tokens:
        if word == ";":
            statements.append([])
        else:
            statements[-1].append(word)
    if len(statements) > 1 and not statements[-1]:
        statements.pop()  # syncoid ends some chains with "; "
    if any(not statement for statement in statements):
        return None
    return statements


def _statement(tokens: list[str], root: str) -> Request | Rejected:
    if tokens[0] == "sudo":
        return Rejected("sudo is not allowed; run syncoid with --no-privilege-elevation")
    redirected = tokens[-3:] == _REDIRECT and tokens[:2] == ["zfs", "receive"]
    body = tokens[:-3] if redirected else tokens
    if any(set(token) <= _PUNCTUATION for token in body):
        return Rejected("shell syntax is not allowed")
    handler = _HANDLERS.get((body[0], body[1])) if len(body) > 1 else None
    if handler is not None:
        return handler(body[2:], root)
    return _probe(body, root)


def _probe(tokens: list[str], root: str) -> Request | Rejected:
    if tokens in _NO_ARGS_PROBES:
        return Reply(0)
    is_command_probe = tokens[:2] == ["command", "-v"] and len(tokens) == 3  # noqa: PLR2004
    if is_command_probe and _PROBED_COMMAND.fullmatch(tokens[2]):
        return Reply(1)
    if tokens[:-1] == _POOL_FEATURE_PROBE and tokens[-1] == names.pool_of(root):
        return Run("zpool", tuple(tokens[1:]))
    return Rejected("only zfs commands and syncoid's probes are allowed")


def _outside(name: str, root: str) -> Rejected:
    return Rejected(f"{name!r} is not a dataset inside {root}")


def _get(args: list[str], root: str) -> Request | Rejected:
    if not args or tuple(args[:-1]) not in _GET_FORMS:
        return Rejected("only the zfs get forms syncoid uses are allowed; use zfs list")
    if not names.in_scope(root, args[-1]):
        return _outside(args[-1], root)
    return Run("zfs", ("get", *args))


def _receive(args: list[str], root: str) -> Request | Rejected:
    if not args:
        return Rejected("zfs receive needs a target dataset")
    *flags, dataset = args
    if not names.strictly_below(root, dataset):
        return _outside(dataset, root)
    if flags == ["-A"]:
        return Run("zfs", ("receive", "-A", dataset))
    if not set(flags) <= {"-s", "-F", "-u"} or len(set(flags)) != len(flags):
        return Rejected("zfs receive only accepts -s, -F, -u, or -A")
    return Receive(dataset=dataset, resumable="-s" in flags, force="-F" in flags)


def _destroy(args: list[str], root: str) -> Request | Rejected:
    if not args:
        return Rejected("zfs destroy needs a target")
    *flags, target = args
    if "@" in target:
        return _destroy_snapshots(flags, target, root)
    if flags not in ([], ["-r"]):
        return Rejected("destroying a dataset only accepts -r")
    if not names.strictly_below(root, target):
        return _outside(target, root)
    return Run("zfs", ("destroy", *flags, target))


def _destroy_snapshots(flags: list[str], target: str, root: str) -> Request | Rejected:
    if flags not in ([], ["-r"]):
        return Rejected("destroying snapshots only accepts -r")
    dataset, _, snapshots = target.partition("@")
    if not names.strictly_below(root, dataset):
        return _outside(dataset, root)
    if not all(names.is_snapshot_name(item) for item in snapshots.split(",")):
        return Rejected(f"invalid snapshot list {snapshots!r}")
    return Run("zfs", ("destroy", *flags, target))


def _destroy_chain(statements: list[list[str]], root: str) -> Request | Rejected:
    targets: list[str] = []
    for statement in statements:
        if len(statement) != 3 or statement[:2] != ["zfs", "destroy"] or "@" not in statement[2]:  # noqa: PLR2004
            return Rejected("only chains of 'zfs destroy dataset@snapshot' are allowed")
        targets.append(statement[2])
    datasets = {target.partition("@")[0] for target in targets}
    if len(datasets) != 1:
        return Rejected("a destroy chain must name a single dataset")
    snapshots = ",".join(target.partition("@")[2] for target in targets)
    return _destroy_snapshots([], f"{datasets.pop()}@{snapshots}", root)


def _create(args: list[str], root: str) -> Request | Rejected:
    if not args:
        return Rejected("zfs create needs a dataset")
    *flags, dataset = args
    if flags not in ([], ["-p"]):
        return Rejected("zfs create only accepts -p")
    if not names.strictly_below(root, dataset):
        return _outside(dataset, root)
    return Run("zfs", ("create", *flags, dataset))


def _csv_within(allowed: frozenset[str]) -> Callable[[str], bool]:
    return lambda value: all(part in allowed for part in value.split(","))


_LIST_OPTIONS: dict[str, Callable[[str], bool]] = {
    "-d": lambda value: _DEPTH.fullmatch(value) is not None,
    "-t": _csv_within(_LIST_TYPES),
    "-o": _csv_within(_LIST_COLUMNS),
    "-s": lambda value: value in _LIST_COLUMNS,
    "-S": lambda value: value in _LIST_COLUMNS,
}


def _list(args: list[str], root: str) -> Request | Rejected:
    built: list[str] = []
    dataset = root
    rest = list(args)
    while rest:
        token = rest.pop(0)
        if _LIST_SWITCHES.fullmatch(token):
            built.append(token)
        elif token in _LIST_OPTIONS and rest:
            value = rest.pop(0)
            if not _LIST_OPTIONS[token](value):
                return Rejected(f"invalid value {value!r} for zfs list {token}")
            built += [token, value]
        elif not rest and not token.startswith("-"):
            dataset = token
        else:
            return Rejected(f"zfs list option {token!r} is not allowed")
    if not names.in_scope(root, dataset):
        return _outside(dataset, root)
    return Run("zfs", ("list", *built, dataset))


def _send(args: list[str], root: str) -> Request | Rejected:
    if len(args) == 2 and args[0] == "-t":  # noqa: PLR2004
        if _RESUME_TOKEN.fullmatch(args[1]) is None:
            return Rejected("invalid resume token")
        return ResumeSend(args[1])
    if not args:
        return Rejected("zfs send needs a snapshot")
    *options, target = args
    parts = names.split_snapshot(target)
    if parts is None or not names.in_scope(root, parts[0]):
        return _outside(target, root)
    built = _send_options(options, parts[0])
    if isinstance(built, Rejected):
        return built
    return Run("zfs", ("send", *built, target))


def _send_options(options: list[str], dataset: str) -> list[str] | Rejected:
    built: list[str] = []
    rest = list(options)
    while rest:
        token = rest.pop(0)
        if _SEND_SWITCHES.fullmatch(token):
            built.append(token)
        elif token in {"-i", "-I"} and rest:
            origin = rest.pop(0)
            if not _origin_of(origin, dataset):
                return Rejected(f"incremental origin {origin!r} must be a snapshot of {dataset}")
            built += [token, origin]
        else:
            return Rejected(f"zfs send option {token!r} is not allowed")
    return built


def _origin_of(origin: str, dataset: str) -> bool:
    if origin.startswith("@"):
        return names.is_snapshot_name(origin[1:])
    parts = names.split_snapshot(origin)
    return parts is not None and parts[0] == dataset


_HANDLERS: dict[tuple[str, str], Callable[[list[str], str], Request | Rejected]] = {
    ("zfs", "get"): _get,
    ("zfs", "receive"): _receive,
    ("zfs", "destroy"): _destroy,
    ("zfs", "create"): _create,
    ("zfs", "list"): _list,
    ("zfs", "send"): _send,
}
