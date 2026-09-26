"""Tests for the captured ZFS runner."""

from __future__ import annotations

import os
import subprocess
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Sequence

    import pytest

from zfs_tenant import zfs


def test_runner_pins_locale_and_preserves_other_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: dict[str, str] = {}

    def fake_run(
        argv: Sequence[str], *, env: dict[str, str], **_kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        seen.update(env)
        return subprocess.CompletedProcess(argv, 0, stdout="ok\n", stderr="")

    monkeypatch.setenv("ZFS_TENANT_SENTINEL", "kept")
    monkeypatch.setenv("LC_ALL", "fr_FR.UTF-8")
    monkeypatch.setattr(subprocess, "run", fake_run)
    assert zfs.run(["/sbin/zfs", "allow", "tank/x"]) == "ok\n"
    assert seen["LC_ALL"] == "C"
    assert seen["ZFS_TENANT_SENTINEL"] == "kept"
    assert os.environ["LC_ALL"] == "fr_FR.UTF-8"
