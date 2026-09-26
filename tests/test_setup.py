"""Tests for idempotent tenant root setup."""

from __future__ import annotations

from types import SimpleNamespace
from typing import TYPE_CHECKING

import pytest

from zfs_tenant import setup, zfs

if TYPE_CHECKING:
    from collections.abc import Sequence

SPEC = setup.TenantSpec(root="tank/friends/joe", user="zfs-tenant-joe", quota="2T")


@pytest.fixture(autouse=True)
def tenant_identity(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "pwd.getpwnam", lambda _user: SimpleNamespace(pw_uid=1001, pw_name="zfs-tenant-joe")
    )


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
    def __init__(
        self,
        feature: str,
        mountpoint: str | None = "/tank/friends/joe\tdefault",
        grants: dict[str, str] | None = None,
        zoned_parent: str = "off",
        display_user: str = "zfs-tenant-joe",
    ) -> None:
        self.feature = feature
        self.mountpoint = mountpoint
        self.grants = grants or {}
        self.zoned_parent = zoned_parent
        self.display_user = display_user
        self.datasets = {"tank", "tank/friends"}
        if mountpoint is not None:
            self.datasets.add(SPEC.root)
        self.calls: list[tuple[str, ...]] = []

    def __call__(self, argv: Sequence[str]) -> str:  # noqa: C901, PLR0911, PLR0912 - test ZFS simulator
        call = tuple(argv)
        self.calls.append(call)
        if call == ("/sbin/zpool", "get", "-H", "-o", "value", "feature@filesystem_limits", "tank"):
            return self.feature + "\n"
        assert call[0] == "/sbin/zfs", f"unexpected command: {call!r}"
        args = call[1:]
        if args[:-1] in {
            ("list", "-H", "-o", "name"),
            ("list", "-H", "-r", "-t", "filesystem,volume", "-o", "name"),
        }:
            name = argv[-1]
            if name not in self.datasets:
                raise zfs.CommandError(tuple(argv), 1, "dataset does not exist")
            if "-r" in argv:
                return (
                    "\n".join(
                        sorted(d for d in self.datasets if d == name or d.startswith(name + "/"))
                    )
                    + "\n"
                )
            return name + "\n"
        if args[:-1] == ("get", "-H", "-o", "value", "zoned"):
            assert args[-1] in self.datasets, f"unexpected dataset: {call!r}"
            return (self.zoned_parent if argv[-1] != SPEC.root else "on") + "\n"
        if args == ("get", "-H", "-o", "value,source", "mountpoint", SPEC.root):
            if self.mountpoint is None:
                raise zfs.CommandError(tuple(argv), 1, "cannot open: dataset does not exist")
            return self.mountpoint + "\n"
        if args[:-1] == ("allow",):
            name = argv[-1]
            assert name in self.datasets, f"unexpected dataset: {call!r}"
            return "".join(
                f"---- Permissions on {source} {'-' * 24}\n{self.grants[source]}"
                for source in (
                    "tank",
                    "tank/friends",
                    SPEC.root,
                    *sorted(self.datasets - {"tank", "tank/friends", SPEC.root}),
                )
                if source in self.grants and (name == source or name.startswith(source + "/"))
            )
        if args == ("create", "-p", SPEC.root):
            parts = argv[-1].split("/")
            self.datasets.update("/".join(parts[:n]) for n in range(1, len(parts) + 1))
            return ""
        if args == ("unallow", "-u", SPEC.user, SPEC.root):
            self.grants.pop(SPEC.root, None)
            return ""
        if args == ("allow", "-l", "-u", SPEC.user, "create,mount,receive", SPEC.root):
            self.grants[SPEC.root] = (
                f"Local permissions:\n\tuser {self.display_user} create,mount,receive\n"
            )
            return ""
        if args == ("allow", "-d", "-u", SPEC.user, "create,destroy,mount,receive,send", SPEC.root):
            self.grants[SPEC.root] = (
                f"Local+Descendent permissions:\n\tuser {self.display_user} create,mount,receive\n"
                f"Descendent permissions:\n\tuser {self.display_user} destroy,send\n"
            )
            return ""
        setting = (
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
            SPEC.root,
        )
        if args in {setting, tuple(arg for arg in setting if arg != "mountpoint=none")}:
            if "mountpoint=none" in args:
                if self.mountpoint == "none\tlocal":
                    raise zfs.CommandError(call, 255, "child dataset is used in a non-global zone")
                self.mountpoint = "none\tlocal"
            return ""
        pytest.fail(f"unexpected command: {call!r}")


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
    mutations = [
        call
        for call in recorder.calls
        if call[1] in {"create", "set", "unallow"} or (call[1] == "allow" and len(call) > 3)
    ]
    assert mutations == [("/sbin/zfs", *args) for args in setup.commands(SPEC)]


def test_apply_refuses_a_pool_without_filesystem_limits() -> None:
    recorder = Recorder("disabled")
    with pytest.raises(setup.SetupError, match="feature@filesystem_limits"):
        setup.apply(SPEC, zfs_path="/sbin/zfs", zpool_path="/sbin/zpool", runner=recorder)
    assert len(recorder.calls) == 1


def test_keep_mountpoint_drops_only_the_mountpoint_write() -> None:
    kept = setup.commands(SPEC, keep_mountpoint=True)
    assert "mountpoint=none" not in kept[1]
    assert [arg for arg in setup.commands(SPEC)[1] if arg != "mountpoint=none"] == kept[1]
    assert kept[2:] == setup.commands(SPEC)[2:]


def test_apply_sets_the_mountpoint_on_a_new_root() -> None:
    recorder = Recorder("active", mountpoint=None)
    setup.apply(SPEC, zfs_path="/sbin/zfs", zpool_path="/sbin/zpool", runner=recorder)
    setting = next(call for call in recorder.calls if call[1] == "set")
    assert "mountpoint=none" in setting


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
    ("grant", "reason"),
    [
        ("Local permissions:\n user zfs-tenant-joe destroy\n", "destroy"),
        # Treating combined grants as descendant-only would permit root destruction.
        ("Local+Descendent permissions:\n user zfs-tenant-joe destroy\n", "destroy"),
        ("Local permissions:\n user another-user create\n", "another-user"),
        ("Local permissions:\n group staff create\n", "group"),
        ("Local permissions:\n everyone create\n", "everyone"),
        ("Permission sets:\n @admin destroy\n", "Permission sets"),
        ("Create time permissions:\n destroy\n", "Create time"),
        ("Unexpected permissions:\n user zfs-tenant-joe create\n", "Unexpected"),
        ("Local permissions:\n user zfs-tenant-joe\n", "malformed"),
        ("Local permissions:\n", "empty"),
        ("Local permissions:\nDescendent permissions:\n user zfs-tenant-joe send\n", "empty"),
    ],
)
def test_existing_unsafe_root_is_rejected_before_mutation(grant: str, reason: str) -> None:
    recorder = Recorder("active", grants={SPEC.root: grant})
    with pytest.raises(setup.SetupError, match=reason):
        setup.apply(SPEC, zfs_path="/sbin/zfs", zpool_path="/sbin/zpool", runner=recorder)
    assert not any(
        call[1] in {"create", "set", "unallow"} or (call[1] == "allow" and len(call) > 3)
        for call in recorder.calls
    )


@pytest.mark.parametrize(
    ("output", "reason"),
    [
        pytest.param(
            "--- Permissions on tank/friends/joe ----\n"
            "Local permissions:\n user zfs-tenant-joe create\n",
            "unknown",
            id="malformed-banner",
        ),
        pytest.param(
            "---- Permissions on tank/friends/joe ----\n"
            "Local permissions:\n user zfs-tenant-joe create\n"
            "---- Permissions on tank/friends/joe ----\n"
            "Descendent permissions:\n user zfs-tenant-joe send\n",
            "duplicate",
            id="repeated-source",
        ),
        pytest.param(
            "---- Permissions on tank/friends/joe ----\n"
            "Local permissions:\n user zfs-tenant-joe create\n"
            "Local permissions:\n user zfs-tenant-joe mount\n",
            "repeated",
            id="repeated-section",
        ),
        pytest.param(
            "---- Permissions on tank/friends/joe ----\n",
            "empty",
            id="empty-source",
        ),
        pytest.param(
            "---- Permissions on tank/friends/joe ----\nLocal permissions:\n",
            "empty",
            id="empty-final-section",
        ),
        pytest.param(
            "---- Permissions on tank/friends ----\nLocal permissions:\n"
            "---- Permissions on tank/friends/joe ----\n"
            "Local permissions:\n user zfs-tenant-joe create\n",
            "empty",
            id="empty-section-before-next-source",
        ),
        pytest.param(
            "---- Permissions on tank/friends/joe ----\n"
            "Local permissions:\n user zfs-tenant-joe create,,mount\n",
            "malformed",
            id="malformed-rights",
        ),
    ],
)
def test_malformed_delegation_output_is_rejected_before_mutation(output: str, reason: str) -> None:
    # Skipping malformed blocks or overwriting repeated ones could hide unsafe grants.
    class MalformedRecorder(Recorder):
        def __call__(self, argv: Sequence[str]) -> str:
            result = super().__call__(argv)
            if tuple(argv) == ("/sbin/zfs", "allow", SPEC.root):
                return output
            return result

    recorder = MalformedRecorder("active")
    with pytest.raises(setup.SetupError, match=reason):
        setup.apply(SPEC, zfs_path="/sbin/zfs", zpool_path="/sbin/zpool", runner=recorder)
    assert not any(
        call[1] in {"create", "set", "unallow"} or (call[1] == "allow" and len(call) > 3)
        for call in recorder.calls
    )


@pytest.mark.parametrize(
    "grant",
    [
        "Local permissions:\n user 1001 create,mount,receive\n",
        (
            "Local permissions:\n user zfs-tenant-joe create,mount,receive\n"
            "Descendent permissions:\n user zfs-tenant-joe create,destroy,mount,receive,send\n"
        ),
        (
            "Local+Descendent permissions:\n user 1001 create,mount,receive\n"
            "Descendent permissions:\n user 1001 destroy,send\n"
        ),
    ],
)
def test_own_existing_grants_are_safe_to_reapply(grant: str) -> None:
    recorder = Recorder("active", grants={SPEC.root: grant})
    setup.apply(SPEC, zfs_path="/sbin/zfs", zpool_path="/sbin/zpool", runner=recorder)
    assert any(call[1] == "set" for call in recorder.calls)


def test_canonical_display_name_is_accepted_for_configured_alias(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "pwd.getpwnam", lambda _user: SimpleNamespace(pw_uid=1001, pw_name="canonical-joe")
    )
    recorder = Recorder(
        "active",
        grants={SPEC.root: "Local permissions:\n user canonical-joe create\n"},
        display_user="canonical-joe",
    )
    setup.apply(SPEC, zfs_path="/sbin/zfs", zpool_path="/sbin/zpool", runner=recorder)
    assert any(call[1] == "set" for call in recorder.calls)


def test_direct_child_grant_is_rejected_before_mutation() -> None:
    recorder = Recorder(
        "active",
        grants={"tank/friends/joe/data": "Local permissions:\n user zfs-tenant-joe create\n"},
    )
    recorder.datasets.add("tank/friends/joe/data")
    with pytest.raises(setup.SetupError, match="tank/friends/joe/data"):
        setup.apply(SPEC, zfs_path="/sbin/zfs", zpool_path="/sbin/zpool", runner=recorder)
    assert not any(call[1] == "set" for call in recorder.calls)


def test_direct_volume_grant_is_rejected_before_mutation() -> None:
    recorder = Recorder(
        "active", grants={"tank/friends/joe/disk": "Descendent permissions:\n user 1001 send\n"}
    )
    recorder.datasets.add("tank/friends/joe/disk")
    with pytest.raises(setup.SetupError, match="tank/friends/joe/disk"):
        setup.apply(SPEC, zfs_path="/sbin/zfs", zpool_path="/sbin/zpool", runner=recorder)
    assert not any(call[1] == "set" for call in recorder.calls)


def test_well_formed_ancestor_grant_is_ignored_across_unzoned_boundary() -> None:
    recorder = Recorder(
        "active", grants={"tank/friends": "Local+Descendent permissions:\n group staff destroy\n"}
    )
    setup.apply(SPEC, zfs_path="/sbin/zfs", zpool_path="/sbin/zpool", runner=recorder)
    assert any(call[1] == "set" for call in recorder.calls)


def test_zoned_parent_rejected_before_mutation() -> None:
    recorder = Recorder("active", zoned_parent="on")
    with pytest.raises(setup.SetupError, match="zoned"):
        setup.apply(SPEC, zfs_path="/sbin/zfs", zpool_path="/sbin/zpool", runner=recorder)
    assert not any(call[1] == "set" for call in recorder.calls)


def test_missing_root_walks_to_existing_unzoned_parent() -> None:
    recorder = Recorder("active", mountpoint=None)
    recorder.datasets.remove("tank/friends")
    setup.apply(SPEC, zfs_path="/sbin/zfs", zpool_path="/sbin/zpool", runner=recorder)
    assert ("/sbin/zfs", "get", "-H", "-o", "value", "zoned", "tank") in recorder.calls
    assert any(call[1] == "set" for call in recorder.calls)


def test_parent_create_time_grant_copied_to_new_root_is_rejected_before_properties() -> None:
    class CopyingRecorder(Recorder):
        def __call__(self, argv: Sequence[str]) -> str:
            result = super().__call__(argv)
            if argv[1] == "create":
                self.grants[SPEC.root] = "Local permissions:\n user creator destroy\n"
            return result

    recorder = CopyingRecorder("active", mountpoint=None)
    with pytest.raises(setup.SetupError, match="creator"):
        setup.apply(SPEC, zfs_path="/sbin/zfs", zpool_path="/sbin/zpool", runner=recorder)
    assert any(call[1] == "create" for call in recorder.calls)
    assert not any(call[1] in {"set", "unallow"} for call in recorder.calls)


def test_final_verification_rejects_missing_grants() -> None:
    class DroppingRecorder(Recorder):
        def __call__(self, argv: Sequence[str]) -> str:
            result = super().__call__(argv)
            if argv[1] == "allow" and "-d" in argv:
                self.grants.pop(SPEC.root, None)
            return result

    with pytest.raises(setup.SetupError, match="final"):
        setup.apply(
            SPEC, zfs_path="/sbin/zfs", zpool_path="/sbin/zpool", runner=DroppingRecorder("active")
        )


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
