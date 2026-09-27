"""Tests for the tenant user namespace helpers that run without root."""

from __future__ import annotations

import os
import pwd
import signal
import subprocess
import sys
from typing import TYPE_CHECKING

import pytest

from zfs_tenant import cli, zone

if TYPE_CHECKING:
    from pathlib import Path

ROOT = "tank/friends/joe"


def test_enter_without_a_pid_file_fails(tmp_path: Path) -> None:
    with pytest.raises(zone.ZoneError, match="not running"):
        zone.enter(tmp_path / "missing.pid")


def test_enter_with_garbage_fails(tmp_path: Path) -> None:
    pid_file = tmp_path / "holder.pid"
    pid_file.write_text("not-a-pid\n")
    with pytest.raises(zone.ZoneError, match="not running"):
        zone.enter(pid_file)


def test_enter_with_a_dead_pid_fails(tmp_path: Path) -> None:
    pid_file = tmp_path / "holder.pid"
    pid_file.write_text("999999999\n")
    with pytest.raises(zone.ZoneError, match="not running"):
        zone.enter(pid_file)


def test_enter_refuses_a_pid_in_our_own_namespace(tmp_path: Path) -> None:
    pid_file = tmp_path / "holder.pid"
    pid_file.write_text(f"{os.getpid()}\n")
    with pytest.raises(zone.ZoneError):
        zone.enter(pid_file)


@pytest.mark.skipif(os.getuid() == 0, reason="needs an unprivileged user")
# pytest-xdist workers run threads; the real `zfs-tenant zone` process is single-threaded.
@pytest.mark.filterwarnings("ignore:This process .* is multi-threaded:DeprecationWarning")
def test_serve_without_root_fails_cleanly_and_restores_the_signal_mask(tmp_path: Path) -> None:
    before = signal.pthread_sigmask(signal.SIG_BLOCK, set())
    user = pwd.getpwuid(os.getuid()).pw_name
    with pytest.raises(zone.ZoneError, match="could not create a user namespace"):
        zone.serve(ROOT, user, tmp_path / "holder.pid", zfs_path="zfs", runner=lambda _argv: "")
    assert signal.pthread_sigmask(signal.SIG_BLOCK, set()) == before
    assert not (tmp_path / "holder.pid").exists()


def test_zone_refuses_a_bad_root(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    argv = ["zone", "--root", "tank", "--user", "nobody", "--pid-file", str(tmp_path / "p")]
    assert cli.main(argv) == 2
    assert "root" in capsys.readouterr().err


def test_gate_fails_closed_when_the_namespace_is_down(tmp_path: Path) -> None:
    marker = tmp_path / "ran"
    fake = tmp_path / "zfs"
    fake.write_text(f'#!/bin/sh\ntouch "{marker}"\n')
    fake.chmod(0o755)
    env = {**os.environ, "SSH_ORIGINAL_COMMAND": "zfs list"}
    argv = [sys.executable, "-m", "zfs_tenant", "gate", "--root", ROOT, "--zfs", str(fake)]
    argv += ["--zone-pid-file", str(tmp_path / "missing.pid")]
    result = subprocess.run(argv, capture_output=True, env=env, check=False)
    assert result.returncode == 1
    assert b"the tenant namespace is not running" in result.stderr
    assert not marker.exists()


def test_dropping_capabilities_as_an_unprivileged_process_leaves_none() -> None:
    # Unprivileged processes hold no capabilities, so this only proves the capset call
    # and the CapEff check work; the VM test covers the namespace case.
    if os.getuid() == 0:
        pytest.skip("needs an unprivileged user")
    zone._drop_capabilities()
