"""Explicit artifact checks: pytest tests/check_pyz.py --wheel WHEEL --pyz PYZ."""

from __future__ import annotations

import subprocess
import sys
from email.parser import BytesParser
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

import pytest

from tests.test_cli import FAKE_ZFS, ROOT, run_gate


@pytest.fixture(scope="session")
def pyz(request: pytest.FixtureRequest) -> Path:
    path = request.config.getoption("--pyz")
    assert path is not None, "pass --pyz with the archive to check"
    return Path(path).resolve(strict=True)


@pytest.fixture(scope="session")
def wheel(request: pytest.FixtureRequest) -> Path:
    path = request.config.getoption("--wheel")
    assert path is not None, "pass --wheel with the wheel used to build the archive"
    return Path(path).resolve(strict=True)


@pytest.fixture
def fake_zfs(tmp_path: Path) -> Path:
    path = tmp_path / "zfs"
    path.write_text(FAKE_ZFS)
    path.chmod(0o755)
    return path


def test_archive_contains_the_wheel_package_and_entry_point(pyz: Path, wheel: Path) -> None:
    assert pyz.read_bytes().startswith(b"#!/usr/bin/env python3\n")
    with ZipFile(wheel) as source, ZipFile(pyz) as archive:
        expected = {
            name: source.read(name)
            for name in source.namelist()
            if name.startswith("zfs_tenant/") and not name.endswith("/")
        }
        expected["__main__.py"] = expected["zfs_tenant/__main__.py"]
        actual = {
            item.filename: archive.read(item) for item in archive.infolist() if not item.is_dir()
        }
        assert actual == expected
        assert all(
            item.compress_type == ZIP_DEFLATED for item in archive.infolist() if not item.is_dir()
        )


def test_archive_version_matches_wheel(pyz: Path, wheel: Path, tmp_path: Path) -> None:
    with ZipFile(wheel) as source:
        [metadata] = [name for name in source.namelist() if name.endswith(".dist-info/METADATA")]
        version = BytesParser().parsebytes(source.read(metadata))["Version"]
    result = subprocess.run(
        [sys.executable, "-I", str(pyz), "--version"],
        cwd=tmp_path,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.decode() == f"zfs-tenant {version}\n"


def test_archive_help(pyz: Path, tmp_path: Path) -> None:
    result = subprocess.run(
        [sys.executable, "-I", str(pyz), "--help"],
        cwd=tmp_path,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert b"usage: zfs-tenant" in result.stdout
    assert b"authorized-key" in result.stdout


@pytest.mark.parametrize(
    ("command", "expected"),
    [
        ("zfs list -r", (0, f"ARGV:list -r {ROOT}\n", "")),
        (f"zfs get -H name {ROOT}", (7, f"ARGV:get -H name {ROOT}\n", "")),
        ("reboot", (126, "", "command not allowed")),
        (None, (126, "", "interactive sessions are not allowed")),
    ],
)
def test_archive_gate_status_and_environment(
    pyz: Path, fake_zfs: Path, command: str | None, expected: tuple[int, str, str]
) -> None:
    status, stdout, stderr = expected
    result = run_gate(fake_zfs, command, pyz=pyz)
    assert result.returncode == status, result.stderr
    assert result.stdout.decode() == stdout
    assert stderr in result.stderr.decode()


def test_archive_passes_binary_stdin_to_receive(pyz: Path, fake_zfs: Path) -> None:
    stream = b"stream\x00bytes\xff\n"
    result = run_gate(fake_zfs, f"zfs receive -s {ROOT}/x", stdin=stream, pyz=pyz)
    assert result.returncode == 0, result.stderr
    assert result.stdout.decode() == f"ARGV:receive -u -s {ROOT}/x\n"
    assert (fake_zfs.parent / "stream").read_bytes() == stream
