"""Tests for OpenZFS name validation and scoping."""

from __future__ import annotations

import pytest

from zfs_tenant import names

ROOT = "tank/friends/joe"


@pytest.mark.parametrize(
    ("name", "tenant_root"),
    [
        ("tank", False),
        ("tank/friends/joe", True),
        ("tank/a.b:c-d_e", True),
        ("tank/friends/joe/offsite/2026", True),
        ("tank/friends/joe2", True),
    ],
)
def test_valid_datasets_and_tenant_roots(name: str, tenant_root: bool) -> None:
    assert names.is_dataset(name)
    assert names.is_tenant_root(name) is tenant_root


@pytest.mark.parametrize(
    "name",
    [
        "",
        "/tank",
        "tank/",
        "tank//x",
        "tank/..",
        "tank/.",
        "tank/-x",
        "-tank",
        "tank/x@s",
        "tank/x y",
        "tank/x'",
        "tank/$(id)",
        "tank/x#b",
        "tank/x%y",
        "tank/ü",
    ],
)
def test_invalid_datasets(name: str) -> None:
    assert not names.is_dataset(name)
    assert not names.is_tenant_root(name)


@pytest.mark.parametrize("name", ["autosnap_2026-09-25_00:00:00_daily", "s1", "syncoid_x.y"])
def test_valid_snapshot_names(name: str) -> None:
    assert names.is_snapshot_name(name)


@pytest.mark.parametrize("name", ["", "-r", "a%b", "a@b", "a/b", "a#b", "a b", "a,b"])
def test_invalid_snapshot_names(name: str) -> None:
    assert not names.is_snapshot_name(name)


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        (ROOT, True),
        (f"{ROOT}/offsite", True),
        (f"{ROOT}/a/b/c", True),
        ("tank/friends/joe2", False),
        ("tank/friends", False),
        ("tank/host", False),
        (f"{ROOT}/../host", False),
        (f"{ROOT}/x@s", False),
    ],
)
def test_in_scope(name: str, expected: bool) -> None:
    assert names.in_scope(ROOT, name) is expected


def test_strictly_below_excludes_root() -> None:
    assert not names.strictly_below(ROOT, ROOT)
    assert names.strictly_below(ROOT, f"{ROOT}/offsite")
    assert not names.strictly_below(ROOT, "tank/friends/joe2/x")


@pytest.mark.parametrize(
    ("full_name", "expected"),
    [
        ("tank/x@s1", ("tank/x", "s1")),
        ("tank/x", None),
        ("tank/x@", None),
        ("@s1", None),
        ("tank/x@a@b", None),
        ("tank/x@a%b", None),
    ],
)
def test_split_snapshot(full_name: str, expected: tuple[str, str] | None) -> None:
    assert names.split_snapshot(full_name) == expected


def test_pool_of() -> None:
    assert names.pool_of("tank/friends/joe") == "tank"
    assert names.pool_of("tank") == "tank"
