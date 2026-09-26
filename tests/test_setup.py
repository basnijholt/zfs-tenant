"""Tests for idempotent tenant root setup."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from zfs_tenant import setup

if TYPE_CHECKING:
    from collections.abc import Sequence

SPEC = setup.TenantSpec(root="tank/friends/joe", user="zfs-tenant-joe", quota="2T")


def test_commands_set_properties_and_delegate() -> None:
    assert setup.commands(SPEC) == [
        ["create", "-p", "tank/friends/joe"],
        [
            "set",
            "quota=2T",
            "reservation=none",
            "filesystem_limit=100",
            "snapshot_limit=20000",
            "mountpoint=none",
            "canmount=off",
            "readonly=on",
            "exec=off",
            "setuid=off",
            "devices=off",
            "volmode=none",
            "zoned=on",
            "tank/friends/joe",
        ],
        ["unallow", "-u", "zfs-tenant-joe", "tank/friends/joe"],
        ["allow", "-l", "-u", "zfs-tenant-joe", "create,mount,receive", "tank/friends/joe"],
        [
            "allow",
            "-d",
            "-u",
            "zfs-tenant-joe",
            "create,destroy,mount,receive,send",
            "tank/friends/joe",
        ],
    ]


def test_reservation_is_applied() -> None:
    spec = setup.TenantSpec(root="tank/friends/joe", user="u", quota="2T", reservation="2T")
    assert "reservation=2T" in setup.commands(spec)[1]


class Recorder:
    def __init__(self, feature: str) -> None:
        self.feature = feature
        self.calls: list[tuple[str, ...]] = []

    def __call__(self, argv: Sequence[str]) -> str:
        self.calls.append(tuple(argv))
        if argv[0] == "/sbin/zpool":
            return self.feature + "\n"
        return ""


def test_apply_checks_the_pool_feature_then_runs_every_command() -> None:
    recorder = Recorder("active")
    setup.apply(SPEC, zfs_path="/sbin/zfs", zpool_path="/sbin/zpool", runner=recorder)
    assert recorder.calls[0] == (
        "/sbin/zpool",
        "get",
        "-H",
        "-o",
        "value",
        "feature@filesystem_limits",
        "tank",
    )
    assert recorder.calls[1:] == [("/sbin/zfs", *args) for args in setup.commands(SPEC)]


def test_apply_refuses_a_pool_without_filesystem_limits() -> None:
    recorder = Recorder("disabled")
    with pytest.raises(setup.SetupError, match="feature@filesystem_limits"):
        setup.apply(SPEC, zfs_path="/sbin/zfs", zpool_path="/sbin/zpool", runner=recorder)
    assert len(recorder.calls) == 1


@pytest.mark.parametrize(
    "spec",
    [
        setup.TenantSpec(root="tank", user="u", quota="1T"),
        setup.TenantSpec(root="tank/x y", user="u", quota="1T"),
        setup.TenantSpec(root="tank/x", user="u;id", quota="1T"),
        setup.TenantSpec(root="tank/x", user="u", quota="lots"),
        setup.TenantSpec(root="tank/x", user="u", quota="1T", reservation="1T;id"),
        setup.TenantSpec(root="tank/x", user="u", quota="1T", filesystem_limit=0),
        setup.TenantSpec(root="tank/x", user="u", quota="1T", snapshot_limit=-1),
    ],
)
def test_validate_rejects_bad_specs(spec: setup.TenantSpec) -> None:
    with pytest.raises(setup.SetupError):
        setup.validate(spec)


def test_validate_accepts_decimal_quotas() -> None:
    setup.validate(setup.TenantSpec(root="tank/x", user="zfs-tenant-joe", quota="1.5T"))
