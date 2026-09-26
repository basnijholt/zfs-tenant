"""Command line: the SSH gate, tenant setup, the tenant namespace, and key lines."""

from __future__ import annotations

import argparse
import os
import shlex
import sys
from pathlib import Path
from typing import TYPE_CHECKING

from zfs_tenant import __version__, gate, names, setup, zfs, zone

if TYPE_CHECKING:
    from collections.abc import Sequence

USAGE_STATUS = 2


def main(argv: Sequence[str] | None = None) -> int:
    """Run the zfs-tenant command line and return its exit status."""
    args = _parser().parse_args(argv)
    status: int = args.handler(args)
    return status


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="zfs-tenant",
        description="Give a friend a quota-capped corner of your ZFS pool for raw encrypted backups.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    commands = parser.add_subparsers(required=True, metavar="COMMAND")

    gate_parser = commands.add_parser(
        "gate", help="SSH forced command: run one allowed zfs command from SSH_ORIGINAL_COMMAND"
    )
    gate_parser.add_argument("--root", required=True, help="tenant root dataset")
    gate_parser.add_argument("--zfs", default="zfs", help="path to zfs")
    gate_parser.add_argument("--zpool", default="zpool", help="path to zpool")
    gate_parser.add_argument(
        "--no-require-encryption",
        action="store_true",
        help="accept unencrypted datasets (by default only raw encrypted sends are kept)",
    )
    gate_parser.add_argument(
        "--zone-pid-file",
        type=Path,
        help="join the tenant namespace whose holder pid is in this file before doing anything",
    )
    gate_parser.set_defaults(handler=_gate)

    setup_parser = commands.add_parser(
        "setup", help="create the tenant root, set its properties, and delegate it (run as root)"
    )
    setup_parser.add_argument("--root", required=True, help="tenant root dataset")
    setup_parser.add_argument("--user", required=True, help="local user the tenant logs in as")
    setup_parser.add_argument("--quota", required=True, help="size cap, e.g. 2T")
    setup_parser.add_argument("--reservation", help="guaranteed space, e.g. 2T")
    setup_parser.add_argument("--filesystem-limit", type=int, default=100)
    setup_parser.add_argument("--snapshot-limit", type=int, default=20000)
    setup_parser.add_argument("--zfs", default="zfs", help="path to zfs")
    setup_parser.add_argument("--zpool", default="zpool", help="path to zpool")
    setup_parser.add_argument(
        "--dry-run", action="store_true", help="print the commands instead of running them"
    )
    setup_parser.set_defaults(handler=_setup)

    zone_parser = commands.add_parser(
        "zone",
        help="keep the tenant's user namespace alive and zfs zone the root to it (run as root)",
    )
    zone_parser.add_argument("--root", required=True, help="tenant root dataset")
    zone_parser.add_argument("--user", required=True, help="local user the tenant logs in as")
    zone_parser.add_argument(
        "--pid-file", type=Path, required=True, help="where the gate finds the holder"
    )
    zone_parser.add_argument("--zfs", default="zfs", help="path to zfs")
    zone_parser.set_defaults(handler=_zone)

    key_parser = commands.add_parser(
        "authorized-key", help="print an authorized_keys line that forces the gate"
    )
    key_parser.add_argument("--gate-command", required=True, help="full gate command line")
    key_parser.add_argument(
        "--from", dest="sources", required=True, help="allowed source addresses"
    )
    key_parser.add_argument("key", nargs="+", help="the tenant's public key")
    key_parser.set_defaults(handler=_authorized_key)
    return parser


def _fail(message: str, status: int = 1) -> int:
    sys.stderr.write(f"zfs-tenant: {message}\n")
    return status


def _gate(args: argparse.Namespace) -> int:
    if not names.is_dataset(args.root) or "/" not in args.root:
        return _fail(f"--root must be a dataset below a pool, got {args.root!r}", USAGE_STATUS)
    if args.zone_pid_file is not None:
        try:
            zone.enter(args.zone_pid_file)
        except zone.ZoneError as error:
            gate.log_to_syslog(f"root={args.root} unavailable: {error}")
            return _fail(str(error))
    config = gate.GateConfig(
        root=args.root,
        zfs=args.zfs,
        zpool=args.zpool,
        require_encryption=not args.no_require_encryption,
    )
    return gate.handle(os.environ.get("SSH_ORIGINAL_COMMAND"), config)


def _setup(args: argparse.Namespace) -> int:
    spec = setup.TenantSpec(
        root=args.root,
        user=args.user,
        quota=args.quota,
        reservation=args.reservation,
        filesystem_limit=args.filesystem_limit,
        snapshot_limit=args.snapshot_limit,
    )
    try:
        if args.dry_run:
            setup.validate(spec)
            for command in setup.commands(spec):
                sys.stdout.write(shlex.join([args.zfs, *command]) + "\n")
            return 0
        setup.apply(spec, zfs_path=args.zfs, zpool_path=args.zpool, runner=zfs.run)
    except (setup.SetupError, zfs.CommandError) as error:
        return _fail(str(error))
    sys.stdout.write(f"zfs-tenant: {spec.root} is ready for {spec.user}\n")
    return 0


def _zone(args: argparse.Namespace) -> int:
    if not names.is_dataset(args.root) or "/" not in args.root:
        return _fail(f"--root must be a dataset below a pool, got {args.root!r}", USAGE_STATUS)
    try:
        return zone.serve(args.root, args.user, args.pid_file, zfs_path=args.zfs, runner=zfs.run)
    except (zone.ZoneError, zfs.CommandError, KeyError) as error:
        return _fail(str(error))


def _authorized_key(args: argparse.Namespace) -> int:
    key = " ".join(args.key)
    fields = (args.gate_command, args.sources, key)
    if any('"' in value or "\n" in value or "\r" in value for value in fields):
        return _fail(
            "the gate command, sources, and key must not contain quotes or newlines", USAGE_STATUS
        )
    sys.stdout.write(f'restrict,from="{args.sources}",command="{args.gate_command}" {key}\n')
    return 0
