"""Tests for executing gate requests with fake side effects."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from zfs_tenant import gate, zfs

if TYPE_CHECKING:
    from collections.abc import Sequence

ROOT = "tank/friends/joe"
DS = f"{ROOT}/offsite"
ZFS = "/sbin/zfs"
ZPOOL = "/sbin/zpool"
CONFIG = gate.GateConfig(root=ROOT, zfs=ZFS, zpool=ZPOOL)
LIST_ENCRYPTION = (ZFS, "list", "-H", "-r", "-t", "filesystem,volume", "-o", "name,encryption", DS)
MISSING = zfs.CommandError(LIST_ENCRYPTION, 1, f"cannot open '{DS}': dataset does not exist\n")
TOKEN = "1-e604ea4bf-e0-789c63a2"


@dataclass
class Fake:
    outputs: dict[tuple[str, ...], list[str | zfs.CommandError]] = field(default_factory=dict)
    runs: list[tuple[str, ...]] = field(default_factory=list)
    spawns: list[tuple[tuple[str, ...], bool]] = field(default_factory=list)
    spawn_status: int = 0
    logs: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def runner(self, argv: Sequence[str]) -> str:
        self.runs.append(tuple(argv))
        queue = self.outputs.get(tuple(argv))
        assert queue, f"no configured response remaining for {tuple(argv)!r}"
        item = queue.pop(0)
        if isinstance(item, zfs.CommandError):
            raise item
        return item

    def spawner(self, argv: Sequence[str], *, merge_stderr: bool) -> int:
        self.spawns.append((tuple(argv), merge_stderr))
        return self.spawn_status

    def effects(self) -> gate._Effects:
        return gate._Effects(
            runner=self.runner,
            spawner=self.spawner,
            log=self.logs.append,
            write_error=self.errors.append,
        )


def test_interactive_session_is_denied() -> None:
    fake = Fake()
    assert gate.handle(None, CONFIG, fake.effects()) == gate._DENIED_STATUS
    assert fake.errors == ["zfs-tenant: interactive sessions are not allowed"]
    assert not fake.spawns


def test_rejected_command_runs_nothing() -> None:
    fake = Fake()
    assert gate.handle("reboot", CONFIG, fake.effects()) == gate._DENIED_STATUS
    assert fake.errors == [
        "zfs-tenant: command not allowed: only zfs commands and syncoid's probes are allowed"
    ]
    assert not fake.spawns
    assert not fake.runs
    assert "denied" in fake.logs[0]


def test_probes_answer_without_running() -> None:
    fake = Fake()
    assert gate.handle("exit", CONFIG, fake.effects()) == 0
    assert gate.handle("command -v mbuffer", CONFIG, fake.effects()) == 1
    assert not fake.spawns


def test_run_spawns_zfs_and_propagates_status() -> None:
    fake = Fake(spawn_status=3)
    assert gate.handle("zfs list", CONFIG, fake.effects()) == 3
    assert fake.spawns == [((ZFS, "list", ROOT), False)]
    assert "allowed" in fake.logs[0]


def test_zpool_probe_uses_zpool_path() -> None:
    fake = Fake()
    gate.handle("zpool get -o value -H feature@extensible_dataset tank", CONFIG, fake.effects())
    assert fake.spawns[0][0][0] == ZPOOL


def test_encrypted_receive_succeeds() -> None:
    fake = Fake(outputs={LIST_ENCRYPTION: [MISSING, f"{DS}\taes-256-gcm\n"]})
    assert gate.handle(f"  zfs receive  -s -F '{DS}' 2>&1", CONFIG, fake.effects()) == 0
    assert fake.spawns == [((ZFS, "receive", "-u", "-s", "-F", DS), True)]


def test_receive_without_force_does_not_request_rollback() -> None:
    fake = Fake(outputs={LIST_ENCRYPTION: [MISSING, f"{DS}\taes-256-gcm\n"]})
    assert gate.handle(f"zfs receive -s {DS}", CONFIG, fake.effects()) == 0
    assert fake.spawns == [((ZFS, "receive", "-u", "-s", DS), True)]


def test_new_plaintext_dataset_is_destroyed() -> None:
    fake = Fake(
        outputs={
            LIST_ENCRYPTION: [MISSING, f"{DS}\toff\n{DS}/child\toff\n"],
            (ZFS, "destroy", "-r", DS): [""],
        }
    )
    assert gate.handle(f"zfs receive {DS}", CONFIG, fake.effects()) == 1
    assert (ZFS, "destroy", "-r", DS) in fake.runs
    assert (ZFS, "destroy", "-r", f"{DS}/child") not in fake.runs
    assert fake.errors == [f"zfs-tenant: refused unencrypted dataset {DS}; send raw (zfs send -w)"]


def test_new_plaintext_child_under_encrypted_dataset_is_destroyed() -> None:
    before = f"{DS}\taes-256-gcm\n"
    after = f"{DS}\taes-256-gcm\n{DS}/child\toff\n"
    fake = Fake(
        outputs={LIST_ENCRYPTION: [before, after], (ZFS, "destroy", "-r", f"{DS}/child"): [""]}
    )
    assert gate.handle(f"zfs receive {DS}", CONFIG, fake.effects()) == 1
    assert (ZFS, "destroy", "-r", f"{DS}/child") in fake.runs
    assert (ZFS, "destroy", "-r", DS) not in fake.runs


def test_encrypted_dataset_replaced_by_plaintext_is_destroyed() -> None:
    # Only reachable if zfs receive -F ever overwrote an encrypted dataset; libzfs refuses today.
    fake = Fake(
        outputs={
            LIST_ENCRYPTION: [f"{DS}\taes-256-gcm\n", f"{DS}\toff\n"],
            (ZFS, "destroy", "-r", DS): [""],
        }
    )
    assert gate.handle(f"zfs receive -F {DS}", CONFIG, fake.effects()) == 1
    assert (ZFS, "destroy", "-r", DS) in fake.runs


def test_existing_plaintext_target_is_refused_before_reading_the_stream() -> None:
    fake = Fake(outputs={LIST_ENCRYPTION: [f"{DS}\toff\n"]})
    assert gate.handle(f"zfs receive {DS}", CONFIG, fake.effects()) == 1
    assert not fake.spawns
    assert "unencrypted" in fake.errors[0]


def test_existing_plaintext_child_survives_receive_of_encrypted_parent() -> None:
    # Removing the before-state comparison would destroy pre-existing plaintext data.
    tree = f"{DS}\taes-256-gcm\n{DS}/child\toff\n"
    fake = Fake(outputs={LIST_ENCRYPTION: [tree, tree]})
    assert gate.handle(f"zfs receive {DS}", CONFIG, fake.effects()) == 0
    assert fake.spawns == [((ZFS, "receive", "-u", DS), True)]
    assert fake.runs == [LIST_ENCRYPTION, LIST_ENCRYPTION]
    assert not fake.errors


def test_failed_post_receive_inspection_does_not_report_success() -> None:
    # A successful receive must not hide a failure to inspect its encryption state.
    error = zfs.CommandError(LIST_ENCRYPTION, 2, "I/O error\n")
    fake = Fake(outputs={LIST_ENCRYPTION: [MISSING, error]})
    assert gate.handle(f"zfs receive {DS}", CONFIG, fake.effects()) == 1
    assert fake.spawns == [((ZFS, "receive", "-u", DS), True)]
    assert fake.runs == [LIST_ENCRYPTION, LIST_ENCRYPTION]
    assert "I/O error" in fake.errors[0]


def test_failed_plaintext_cleanup_does_not_report_success() -> None:
    # Cleanup errors must reach the caller, not become a successful receive.
    destroy = (ZFS, "destroy", "-r", DS)
    error = zfs.CommandError(destroy, 2, "dataset is busy\n")
    fake = Fake(outputs={LIST_ENCRYPTION: [MISSING, f"{DS}\toff\n"], destroy: [error]})
    assert gate.handle(f"zfs receive {DS}", CONFIG, fake.effects()) == 1
    assert destroy in fake.runs
    assert "dataset is busy" in fake.errors[0]


def test_failed_receive_skips_the_post_check() -> None:
    fake = Fake(outputs={LIST_ENCRYPTION: [MISSING]}, spawn_status=1)
    assert gate.handle(f"zfs receive {DS}", CONFIG, fake.effects()) == 1
    assert fake.runs == [LIST_ENCRYPTION]


def test_receive_without_encryption_policy_skips_checks() -> None:
    fake = Fake()
    config = gate.GateConfig(root=ROOT, zfs=ZFS, zpool=ZPOOL, require_encryption=False)
    assert gate.handle(f"zfs receive {DS}", config, fake.effects()) == 0
    assert not fake.runs


def test_unexpected_zfs_error_is_reported() -> None:
    boom = zfs.CommandError(LIST_ENCRYPTION, 2, "I/O error\n")
    fake = Fake(outputs={LIST_ENCRYPTION: [boom]})
    assert gate.handle(f"zfs receive {DS}", CONFIG, fake.effects()) == 1
    assert "I/O error" in fake.errors[0]
    assert not fake.spawns


def describe(toname: str) -> str:
    return (
        "resume token contents:\nnvlist version: 0\n\tobject = 0x1\n"
        f"\ttoname = {toname}\nfull\t{toname}\t123\nsize\t123\n"
    )


def test_resume_send_in_scope_spawns_send() -> None:
    fake = Fake(outputs={(ZFS, "send", "-nvP", "-t", TOKEN): [describe(f"{DS}@s1")]})
    assert gate.handle(f"zfs send -t {TOKEN}", CONFIG, fake.effects()) == 0
    assert fake.spawns == [((ZFS, "send", "-t", TOKEN), False)]


def test_resume_send_outside_scope_is_denied() -> None:
    fake = Fake(outputs={(ZFS, "send", "-nvP", "-t", TOKEN): [describe("tank/host@s1")]})
    assert gate.handle(f"zfs send -t {TOKEN}", CONFIG, fake.effects()) == gate._DENIED_STATUS
    assert not fake.spawns


def test_unreadable_resume_token_fails() -> None:
    error = zfs.CommandError((ZFS, "send"), 255, "invalid token\n")
    fake = Fake(outputs={(ZFS, "send", "-nvP", "-t", TOKEN): [error]})
    assert gate.handle(f"zfs send -t {TOKEN}", CONFIG, fake.effects()) == 1
    assert not fake.spawns
