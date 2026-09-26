"""Tests for idempotent tenant root setup."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from zfs_tenant import setup, zfs

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
    def __init__(self, feature: str, mountpoint: str = "/tank/friends/joe\tdefault") -> None:
        self.feature = feature
        self.mountpoint = mountpoint
        self.calls: list[tuple[str, ...]] = []

    def __call__(self, argv: Sequence[str]) -> str:
        self.calls.append(tuple(argv))
        if argv[0] == "/sbin/zpool":
            return self.feature + "\n"
        if argv[1] == "get":
            return self.mountpoint + "\n"
        if argv[1] == "set" and "mountpoint=none" in argv and self.mountpoint == "none\tlocal":
            raise zfs.CommandError(tuple(argv), 255, "child dataset is used in a non-global zone")
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
    assert recorder.calls[2] == (
        "/sbin/zfs",
        "get",
        "-H",
        "-o",
        "value,source",
        "mountpoint",
        "tank/friends/joe",
    )
    mutations = [call for call in recorder.calls[1:] if call[1] != "get"]
    assert mutations == [("/sbin/zfs", *args) for args in setup.commands(SPEC)]


def test_apply_refuses_a_pool_without_filesystem_limits() -> None:
    recorder = Recorder("disabled")
    with pytest.raises(setup.SetupError, match="feature@filesystem_limits"):
        setup.apply(SPEC, zfs_path="/sbin/zfs", zpool_path="/sbin/zpool", runner=recorder)
    assert len(recorder.calls) == 1


def test_apply_preserves_an_already_local_mountpoint_on_a_populated_root() -> None:
    recorder = Recorder("active", mountpoint="none\tlocal")
    setup.apply(SPEC, zfs_path="/sbin/zfs", zpool_path="/sbin/zpool", runner=recorder)
    setting = next(call for call in recorder.calls if call[1] == "set")
    assert "mountpoint=none" not in setting
    assert "quota=2T" in setting
    assert "zoned=on" in setting
    assert any(call[1] == "allow" for call in recorder.calls)


@pytest.mark.parametrize("mountpoint", ["/old\tlocal", "none\tinherited from tank/friends"])
def test_apply_enforces_a_local_mountpoint_when_not_already_configured(mountpoint: str) -> None:
    recorder = Recorder("active", mountpoint=mountpoint)
    setup.apply(SPEC, zfs_path="/sbin/zfs", zpool_path="/sbin/zpool", runner=recorder)
    setting = next(call for call in recorder.calls if call[1] == "set")
    assert "mountpoint=none" in setting


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
