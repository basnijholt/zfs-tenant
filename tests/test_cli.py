"""Tests for the zfs-tenant command line."""

from __future__ import annotations

import os
import subprocess
import sys
from typing import TYPE_CHECKING

import pytest

from zfs_tenant import __version__, cli

if TYPE_CHECKING:
    from pathlib import Path

ROOT = "tank/friends/joe"

FAKE_ZFS = """#!/bin/sh
echo "ARGV:$*"
case "$1" in
  receive) cat > "$(dirname "$0")/stream" ;;
  get) exit 7 ;;
esac
"""


@pytest.fixture
def fake_zfs(tmp_path: Path) -> Path:
    path = tmp_path / "zfs"
    path.write_text(FAKE_ZFS)
    path.chmod(0o755)
    return path


def run_gate(
    fake: Path, command: str | None, stdin: bytes = b"", *, pyz: Path | None = None
) -> subprocess.CompletedProcess[bytes]:
    env = {key: value for key, value in os.environ.items() if key != "SSH_ORIGINAL_COMMAND"}
    if command is not None:
        env["SSH_ORIGINAL_COMMAND"] = command
    argv = [sys.executable, "-m", "zfs_tenant"] if pyz is None else [sys.executable, "-I", str(pyz)]
    argv += ["gate", "--root", ROOT]
    argv += ["--zfs", str(fake), "--zpool", str(fake), "--no-require-encryption"]
    return subprocess.run(
        argv, input=stdin, capture_output=True, env=env, cwd=fake.parent, check=False
    )


def test_gate_runs_allowed_commands(fake_zfs: Path) -> None:
    result = run_gate(fake_zfs, "zfs list -r")
    assert result.returncode == 0
    assert result.stdout.decode() == f"ARGV:list -r {ROOT}\n"


def test_gate_propagates_exit_status(fake_zfs: Path) -> None:
    assert run_gate(fake_zfs, f"zfs get -H name {ROOT}").returncode == 7


def test_gate_passes_the_stream_through(fake_zfs: Path) -> None:
    result = run_gate(fake_zfs, f"zfs receive -s {ROOT}/x", stdin=b"stream-bytes")
    assert result.returncode == 0
    assert (fake_zfs.parent / "stream").read_bytes() == b"stream-bytes"
    assert f"ARGV:receive -u -s {ROOT}/x" in result.stdout.decode()


def test_gate_denies_other_commands(fake_zfs: Path) -> None:
    result = run_gate(fake_zfs, "reboot")
    assert result.returncode == 126
    assert b"zfs-tenant: command not allowed" in result.stderr
    assert result.stdout == b""


def test_gate_denies_interactive_sessions(fake_zfs: Path) -> None:
    result = run_gate(fake_zfs, None)
    assert result.returncode == 126
    assert b"interactive sessions are not allowed" in result.stderr


def test_gate_refuses_a_bad_root(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["gate", "--root", "tank"]) == 2
    assert "root" in capsys.readouterr().err


def test_authorized_key_line(capsys: pytest.CaptureFixture[str]) -> None:
    status = cli.main(
        [
            "authorized-key",
            "--gate-command",
            "/usr/bin/python3 /mnt/tank/zfs-tenant.pyz gate --root tank/friends/joe",
            "--from",
            "100.64.0.12",
            "ssh-ed25519",
            "AAAAC3Nza",
            "joe@laptop",
        ]
    )
    assert status == 0
    assert capsys.readouterr().out == (
        'restrict,from="100.64.0.12",command="/usr/bin/python3 /mnt/tank/zfs-tenant.pyz '
        'gate --root tank/friends/joe" ssh-ed25519 AAAAC3Nza joe@laptop\n'
    )


def test_authorized_key_rejects_quotes(capsys: pytest.CaptureFixture[str]) -> None:
    status = cli.main(["authorized-key", "--gate-command", 'x"y', "--from", "1.2.3.4", "k"])
    assert status == 2
    assert "quotes" in capsys.readouterr().err


def test_setup_dry_run_prints_commands(capsys: pytest.CaptureFixture[str]) -> None:
    argv = ["setup", "--root", ROOT, "--user", "zfs-tenant-joe", "--quota", "2T", "--dry-run"]
    assert cli.main(argv) == 0
    out = capsys.readouterr().out
    assert "zpool set feature@filesystem_limits=enabled tank" not in out
    assert f"zfs create -p {ROOT}" in out
    assert f"zfs allow -d -u zfs-tenant-joe create,destroy,mount,receive,send {ROOT}" in out


def test_setup_reports_invalid_specs(capsys: pytest.CaptureFixture[str]) -> None:
    argv = ["setup", "--root", ROOT, "--user", "zfs-tenant-joe", "--quota", "lots", "--dry-run"]
    assert cli.main(argv) == 1
    assert "invalid quota" in capsys.readouterr().err


def test_version(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exit_info:
        cli.main(["--version"])
    assert exit_info.value.code == 0
    assert __version__ in capsys.readouterr().out
