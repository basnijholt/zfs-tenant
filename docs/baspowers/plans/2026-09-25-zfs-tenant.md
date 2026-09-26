# zfs-tenant Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use baspowers:subagent-driven-development (recommended) or baspowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A publish-ready `zfs-tenant` package, NixOS host and sender modules, and a VM-tested setup that lets a friend push raw encrypted syncoid backups into one quota-capped dataset subtree through an SSH forced-command gate.

**Architecture:** OpenZFS delegation (`zfs allow -l`/`-d`) plus root-owned properties form the security boundary; a stdlib-only Python gate, installed as an `authorized_keys` forced command, parses `SSH_ORIGINAL_COMMAND` into a small set of typed requests scoped to the tenant root and exec's `zfs` with an argv it builds itself.
A `setup` command applies the dataset, properties, and delegation idempotently; a `sweep` command implements grace-period holds.
NixOS modules wire users, keys, setup, sweep (host) and non-root syncoid push timers (sender); a two-node NixOS VM test runs real syncoid 2.3.0 against real OpenZFS.

**Tech Stack:** Python >= 3.10 (standard library only), hatchling + hatch-vcs, uv, ruff, mypy, ty, pytest, prek/pre-commit, Nix flakes, NixOS test driver, GitHub Actions.

**Spec:** `docs/baspowers/specs/2026-09-25-zfs-tenant-design.md`

## Global Constraints

- Distribution `zfs-tenant`, import package `zfs_tenant`, console script `zfs-tenant = "zfs_tenant.cli:main"`.
- `requires-python = ">=3.10"`, `dependencies = []` (standard library only; the gate must run from a `.pyz` on TrueNAS SCALE).
- Denied commands exit `126` and print `zfs-tenant: command not allowed: <reason>` to stderr.
- Interactive sessions print `zfs-tenant: interactive sessions are not allowed` and exit `126`.
- Grace hold tag: `zfs-tenant-grace`.
- Root properties: `mountpoint=none canmount=off readonly=on exec=off setuid=off devices=off volmode=none sharenfs=off sharesmb=off`, plus `quota`, `reservation` (default `none`), `filesystem_limit` (default `100`), `snapshot_limit` (default `20000`).
- Delegation: `zfs allow -l -u U create,mount,receive R` and `zfs allow -d -u U create,destroy,mount,receive,send R`, after `zfs unallow -u U R`.
- NixOS option roots: `services.zfs-tenant` (host) and `services.zfs-tenant-sender` (sender); tenant users default to `zfs-tenant-<name>`; the sender user is `zfs-tenant-sender`.
- Sender syncoid flags: `--no-privilege-elevation --no-sync-snap --sendoptions=w --compress=none`.
- Repository `~/Work/zfs-tenant`, remote `github.com/basnijholt/zfs-tenant` (public). Commits use plain English messages without AI attribution trailers, and must be signed (`commit.gpgsign=true`); never pass `--no-gpg-sign`.
- Scaffolding mirrors `basnijholt/pytest-shm`.

## Execution Notes

Deviations recorded while executing this plan; the code is the reference where they differ from the task text below.

- `sweep.sweep` takes a `Grace(days, tag=DEFAULT_TAG)` value object: `sweep(roots, grace, *, zfs_path, runner, now)` (ruff PLR0913).
- The sender delegates `send,hold`, not just `send`: `zfs send -I` takes temporary holds (`cannot hold: permission denied` in the VM test).
- The VM test's `allowedFrom` lists the sender's IPv4 and IPv6 addresses; `/etc/hosts` maps node names to both families.
- The VM test prunes only after a new snapshot: syncoid skips `--delete-target-snapshots` when there is nothing new to send.
- `pyproject.toml` sets `fallback-version = "0.0.0"` for hatch-vcs, and a stub README exists from Task 1 because hatchling requires it.
- Unknown commands are rejected with `only zfs commands and syncoid's probes are allowed`.
- Commit steps stage files by name: a local hook blocks `git add -A`.
- Scope change after the first full implementation, decided by the owner: grace-period holds (Task 5, `sweep.py`, the sweep timer, deferred `destroy -d`, `%` ranges) were removed because they were not an owner requirement, and `zfs zone` was added: `src/zfs_tenant/zone.py` (holder process run as root by `zfs-tenant zone`, `setns` plus capability drop in the gate via `--zone-pid-file`), `zoned=on` in setup, a `zfs-tenant-zone-<name>` unit in the host module, and zone subtests in the VM test. See the spec's zone.py section for the verified semantics.

## File Map

| File | Responsibility |
|---|---|
| `src/zfs_tenant/__init__.py` | version |
| `src/zfs_tenant/__main__.py` | `python -m zfs_tenant` |
| `src/zfs_tenant/names.py` | name validation and scoping |
| `src/zfs_tenant/grammar.py` | command string to typed request (pure) |
| `src/zfs_tenant/zfs.py` | captured subprocess runner, `CommandError` |
| `src/zfs_tenant/gate.py` | request execution, encryption policy, syslog |
| `src/zfs_tenant/setup.py` | idempotent tenant root and delegation |
| `src/zfs_tenant/sweep.py` | grace-period holds |
| `src/zfs_tenant/cli.py` | argparse entry point |
| `tests/test_*.py` | unit tests per module |
| `flake.nix`, `nix/*.nix`, `nix/integration/*` | package, modules, checks, VM test, throwaway test keys |
| `README.md`, `docs/logo.svg`, `CLAUDE.md` | documentation |
| `.github/**`, `justfile`, `.pre-commit-config.yaml`, `pyproject.toml` | tooling |

---

### Task 1: Scaffolding and name validation

**Files:**
- Create: `pyproject.toml`, `.gitignore`, `LICENSE`, `.python-version`, `.envrc`, `justfile`, `.pre-commit-config.yaml`
- Create: `src/zfs_tenant/__init__.py`, `src/zfs_tenant/__main__.py`, `src/zfs_tenant/py.typed`, `src/zfs_tenant/names.py`
- Test: `tests/__init__.py`, `tests/test_names.py`

**Interfaces:**
- Produces: `names.is_dataset(name: str) -> bool`, `names.is_snapshot_name(name: str) -> bool`, `names.in_scope(root: str, name: str) -> bool`, `names.strictly_below(root: str, name: str) -> bool`, `names.split_snapshot(full_name: str) -> tuple[str, str] | None`, `names.pool_of(name: str) -> str`.

- [ ] **Step 1: Write `pyproject.toml`**

```toml
[project]
name = "zfs-tenant"
dynamic = ["version"]
description = "Give a friend a quota-capped corner of your ZFS pool for raw encrypted backups, without giving them a shell"
readme = "README.md"
license = "MIT"
license-files = ["LICENSE"]
authors = [
    { name = "Bas Nijholt", email = "bas@nijho.lt" }
]
maintainers = [
    { name = "Bas Nijholt", email = "bas@nijho.lt" }
]
requires-python = ">=3.10"
keywords = [
    "zfs",
    "openzfs",
    "backup",
    "syncoid",
    "sanoid",
    "ssh",
    "forced-command",
    "delegation",
    "nixos",
]
classifiers = [
    "Development Status :: 4 - Beta",
    "Environment :: Console",
    "Intended Audience :: System Administrators",
    "License :: OSI Approved :: MIT License",
    "Operating System :: POSIX :: Linux",
    "Programming Language :: Python :: 3",
    "Programming Language :: Python :: 3.10",
    "Programming Language :: Python :: 3.11",
    "Programming Language :: Python :: 3.12",
    "Programming Language :: Python :: 3.13",
    "Programming Language :: Python :: 3.14",
    "Topic :: Security",
    "Topic :: System :: Archiving :: Backup",
    "Topic :: System :: Filesystems",
    "Typing :: Typed",
]
dependencies = []

[project.urls]
Homepage = "https://github.com/basnijholt/zfs-tenant"
Repository = "https://github.com/basnijholt/zfs-tenant"
Documentation = "https://github.com/basnijholt/zfs-tenant#readme"
Issues = "https://github.com/basnijholt/zfs-tenant/issues"
Changelog = "https://github.com/basnijholt/zfs-tenant/releases"

[project.scripts]
zfs-tenant = "zfs_tenant.cli:main"

[build-system]
requires = ["hatchling", "hatch-vcs"]
build-backend = "hatchling.build"

[tool.hatch.version]
source = "vcs"

[tool.hatch.build.hooks.vcs]
version-file = "src/zfs_tenant/_version.py"

[tool.hatch.build.targets.wheel]
packages = ["src/zfs_tenant"]

[tool.hatch.build.targets.sdist]
include = ["src", "tests", "README.md", "LICENSE"]

[tool.ruff]
target-version = "py310"
line-length = 100

[tool.ruff.lint]
select = ["ALL"]
ignore = [
    "CPY001",  # no copyright headers; LICENSE covers the project
    "D203",    # incompatible with D211
    "D213",    # incompatible with D212
    "E501",    # formatter handles line length
    "COM812",  # avoid formatter conflicts
    "ISC001",  # avoid formatter conflicts
]

[tool.ruff.lint.per-file-ignores]
"tests/*" = ["S101", "S603", "PLR2004", "D103", "ARG001", "FBT001"]  # relaxed for tests

[tool.mypy]
python_version = "3.10"
strict = true

[[tool.mypy.overrides]]
module = "zfs_tenant._version"
ignore_missing_imports = true

[tool.pytest.ini_options]
testpaths = ["tests"]

[tool.ty.environment]
python-version = "3.10"

[tool.ty.src]
exclude = [
    "src/zfs_tenant/_version.py",  # Generated at build time
]

[dependency-groups]
dev = [
    "mypy>=1.19.0",
    "pre-commit>=4.5.0",
    "pytest>=9.0.2",
    "pytest-xdist>=3.8.0",
    "ruff>=0.16.0",
    "ty>=0.0.1a13",
]
```

- [ ] **Step 2: Write the small tooling files**

`.gitignore`:

```gitignore
__pycache__/
*.py[cod]
.venv/
dist/
build/
.pytest_cache/
.mypy_cache/
.ruff_cache/
src/zfs_tenant/_version.py
result
result-*
```

`LICENSE`: the MIT license text with `Copyright (c) 2026 Bas Nijholt`.

`.python-version`:

```text
3.14
```

`.envrc`:

```bash
source .venv/bin/activate
```

`justfile`:

```just
# zfs-tenant Development Commands
# Run `just` to see available commands

# Default: list available commands
default:
    @just --list

# Install development dependencies
install:
    uv sync --dev

# Run the unit tests (parallel)
test:
    uv run pytest -n auto

# Lint, format, and type check
lint:
    uv run ruff check --fix .
    uv run ruff format .
    uv run mypy src tests
    uv run ty check

# Build the single-file zipapp used on hosts without pip (e.g. TrueNAS SCALE)
pyz:
    rm -rf build/pyz && mkdir -p build/pyz dist
    uv build --wheel --out-dir build/wheel
    cp -r src/zfs_tenant build/pyz/
    printf 'from zfs_tenant.cli import main\nraise SystemExit(main())\n' > build/pyz/__main__.py
    python3 -m zipapp build/pyz -p "/usr/bin/env python3" -o dist/zfs-tenant.pyz
    python3 dist/zfs-tenant.pyz --version

# Run the two-node NixOS VM test against real OpenZFS and syncoid
vm-test:
    nix build .#checks.x86_64-linux.integration --no-link -L

# Clean up build artifacts and caches
clean:
    rm -rf .pytest_cache .mypy_cache .ruff_cache dist build result
    find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
```

The `uv build --wheel` step exists to make hatch-vcs write `src/zfs_tenant/_version.py` before the copy.

`.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v6.0.0
    hooks:
      - id: trailing-whitespace
      - id: end-of-file-fixer
      - id: check-yaml
      - id: check-added-large-files
      - id: check-merge-conflict
      - id: debug-statements

  - repo: https://github.com/astral-sh/ruff-pre-commit
    rev: v0.16.9
    hooks:
      - id: ruff-check
        args: [--fix]
      - id: ruff-format

  - repo: local
    hooks:
      - id: mypy
        name: mypy (type checker)
        entry: uv run mypy src tests
        language: system
        types: [python]
        pass_filenames: false

      - id: ty
        name: ty (type checker)
        entry: uv run ty check
        language: system
        types: [python]
        pass_filenames: false
```

- [ ] **Step 3: Write the package skeleton**

`src/zfs_tenant/__init__.py`:

```python
"""Give a friend a quota-capped corner of your ZFS pool for raw encrypted backups."""

from __future__ import annotations

try:
    from zfs_tenant._version import __version__
except ImportError:  # pragma: no cover - source tree without a build
    __version__ = "0.0.0"

__all__ = ["__version__"]
```

`src/zfs_tenant/__main__.py`:

```python
"""Allow ``python -m zfs_tenant``."""

from zfs_tenant.cli import main

raise SystemExit(main())
```

`src/zfs_tenant/py.typed`: empty file. `tests/__init__.py`: empty file.

- [ ] **Step 4: Write the failing name tests**

`tests/test_names.py`:

```python
"""Tests for OpenZFS name validation and scoping."""

from __future__ import annotations

import pytest

from zfs_tenant import names

ROOT = "tank/friends/joe"


@pytest.mark.parametrize(
    "name",
    ["tank", "tank/friends/joe", "tank/a.b:c-d_e", "tank/friends/joe/offsite/2026"],
)
def test_valid_datasets(name: str) -> None:
    assert names.is_dataset(name)


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
```

- [ ] **Step 5: Run the tests to verify they fail**

Run: `uv sync --dev && uv run pytest tests/test_names.py -q`
Expected: FAIL with `ImportError: cannot import name 'names'`.

- [ ] **Step 6: Implement `src/zfs_tenant/names.py`**

```python
"""Validate OpenZFS names and keep them inside a tenant root."""

from __future__ import annotations

import re

_COMPONENT = re.compile(r"[A-Za-z0-9_.:-]+")
_SNAPSHOT = re.compile(r"[A-Za-z0-9_.:-]+")


def is_dataset(name: str) -> bool:
    """Return whether *name* is a filesystem or volume name this package accepts."""
    return all(
        _COMPONENT.fullmatch(part) is not None
        and part not in {".", ".."}
        and not part.startswith("-")
        for part in name.split("/")
    )


def is_snapshot_name(name: str) -> bool:
    """Return whether *name* is an acceptable snapshot name (the part after ``@``)."""
    return _SNAPSHOT.fullmatch(name) is not None and not name.startswith("-")


def in_scope(root: str, name: str) -> bool:
    """Return whether dataset *name* is *root* or one of its descendants."""
    return is_dataset(name) and (name == root or name.startswith(root + "/"))


def strictly_below(root: str, name: str) -> bool:
    """Return whether dataset *name* is a descendant of *root*, excluding *root* itself."""
    return name != root and in_scope(root, name)


def split_snapshot(full_name: str) -> tuple[str, str] | None:
    """Split ``dataset@snapshot`` into its parts, or return None if it is not one."""
    dataset, separator, snapshot = full_name.partition("@")
    if not separator or not is_dataset(dataset) or not is_snapshot_name(snapshot):
        return None
    return dataset, snapshot


def pool_of(name: str) -> str:
    """Return the pool component of a dataset name."""
    return name.split("/", 1)[0]
```

- [ ] **Step 7: Run the tests to verify they pass**

Run: `uv run pytest tests/test_names.py -q`
Expected: PASS (all tests).

- [ ] **Step 8: Commit**

```bash
git add -A
git commit -m "Add package scaffolding and dataset name validation"
```

---

### Task 2: Command grammar

**Files:**
- Create: `src/zfs_tenant/grammar.py`
- Test: `tests/test_grammar.py`

**Interfaces:**
- Consumes: `names.*` from Task 1.
- Produces: frozen dataclasses `Reply(status: int)`, `Run(program: Literal["zfs", "zpool"], args: tuple[str, ...])`, `Receive(dataset: str, resumable: bool)`, `ResumeSend(token: str)`, `Rejected(reason: str)`; type alias `Request = Reply | Run | Receive | ResumeSend`; `tokenize(command: str) -> list[str] | None`; `parse(command: str, root: str) -> Request | Rejected`.

- [ ] **Step 1: Write the failing grammar tests**

`tests/test_grammar.py`:

```python
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
    (f"  zfs receive  -s -F '{DS}' 2>&1", Receive(DS, resumable=True)),
    (f"  zfs receive  '{DS}' 2>&1", Receive(DS, resumable=False)),
    (f"zfs receive -u {ROOT}/x", Receive(f"{ROOT}/x", resumable=False)),
    (f"zfs receive -A '{DS}'", zfs("receive", "-A", DS)),
    (
        f" zfs destroy '{DS}'@autosnap_a,autosnap_b",
        zfs("destroy", "-d", f"{DS}@autosnap_a,autosnap_b"),
    ),
    (
        f" zfs destroy '{DS}'@syncoid_a;  zfs destroy '{DS}'@syncoid_b",
        zfs("destroy", "-d", f"{DS}@syncoid_a,syncoid_b"),
    ),
    (f"zfs destroy {DS}@%", zfs("destroy", "-d", f"{DS}@%")),
    (f"zfs destroy -r {ROOT}/old@a%b", zfs("destroy", "-d", "-r", f"{ROOT}/old@a%b")),
    (f"zfs destroy -d {DS}@s1", zfs("destroy", "-d", f"{DS}@s1")),
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
    f"zfs receive -o mountpoint=/etc {ROOT}/x 2>&1",
    f"zfs receive -x mountpoint {ROOT}/x",
    f"zfs receive -s -s {ROOT}/x",
    f"zfs receive {ROOT}/x 2>/tmp/f",
    f" mbuffer  -q -s 128k -m 16M | lzop -dfc |  zfs receive  -s -F '{ROOT}/x' 2>&1",
    f"zfs list 2>&1",
    f"zfs destroy {ROOT}",
    f"zfs destroy -r {ROOT}",
    f"zfs destroy -f {ROOT}/x",
    f"zfs destroy -R {ROOT}/x@s",
    f"zfs destroy -d {ROOT}/x",
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
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `uv run pytest tests/test_grammar.py -q`
Expected: FAIL with `ModuleNotFoundError: No module named 'zfs_tenant.grammar'`.

- [ ] **Step 3: Implement `src/zfs_tenant/grammar.py`**

```python
"""Turn an SSH_ORIGINAL_COMMAND string into one allowed request, or reject it.

Pure functions only: no I/O and no ZFS calls. The gate executes what this returns,
always with an argv built here and never through a shell.
"""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal

from zfs_tenant import names

if TYPE_CHECKING:
    from collections.abc import Callable


@dataclass(frozen=True)
class Reply:
    """Answer a probe without running anything."""

    status: int


@dataclass(frozen=True)
class Run:
    """Run ``zfs`` or ``zpool`` with arguments the grammar built."""

    program: Literal["zfs", "zpool"]
    args: tuple[str, ...]


@dataclass(frozen=True)
class Receive:
    """Receive a stream from stdin into a dataset strictly below the root."""

    dataset: str
    resumable: bool


@dataclass(frozen=True)
class ResumeSend:
    """Resume an interrupted send; the gate checks which dataset the token names."""

    token: str


@dataclass(frozen=True)
class Rejected:
    """The command is not allowed; *reason* depends only on the input, so it is safe to show."""

    reason: str


Request = Reply | Run | Receive | ResumeSend

_PUNCTUATION = frozenset(";|&<>")
_REDIRECT = ["2", ">&", "1"]
_PROBED_COMMAND = re.compile(r"[a-z0-9]+")
_RESUME_TOKEN = re.compile(r"[0-9a-f]+(?:-[0-9a-f]+){3}")
_SNAPSHOT_RANGE = re.compile(r"([A-Za-z0-9_.:-]*)%([A-Za-z0-9_.:-]*)")
_LIST_SWITCHES = re.compile(r"-[Hpr]+")
_SEND_SWITCHES = re.compile(r"-[wLceRp]+")
_DEPTH = re.compile(r"[0-9]{1,3}")
_LIST_TYPES = frozenset({"filesystem", "volume", "snapshot", "bookmark", "all"})
_LIST_COLUMNS = frozenset(
    {
        "name",
        "used",
        "available",
        "avail",
        "referenced",
        "refer",
        "logicalused",
        "creation",
        "type",
        "encryption",
        "keystatus",
        "encryptionroot",
        "userrefs",
        "defer_destroy",
        "quota",
        "filesystem_count",
        "snapshot_count",
        "filesystem_limit",
        "snapshot_limit",
        "receive_resume_token",
        "guid",
    }
)
_GET_FORMS = frozenset(
    {
        ("-H", "name"),
        ("-H", "receive_resume_token"),
        ("-H", "-p", "used"),
        ("-Hpd", "1", "-t", "snapshot", "guid,creation"),
        ("-Hpd", "1", "type,guid,creation"),
    }
)
_NO_ARGS_PROBES = (["exit"], ["echo", "-n"], ["ps", "-Ao", "args="])
_POOL_FEATURE_PROBE = ["zpool", "get", "-o", "value", "-H", "feature@extensible_dataset"]


def tokenize(command: str) -> list[str] | None:
    """Split *command* like a POSIX shell, keeping runs of ``;|&<>`` as separate tokens.

    Returns None for control characters or unbalanced quotes.
    """
    if any(ord(char) < 0x20 or ord(char) == 0x7F for char in command):  # noqa: PLR2004
        return None
    lexer = shlex.shlex(command, posix=True, punctuation_chars=";|&<>")
    lexer.whitespace_split = True
    lexer.commenters = ""
    try:
        return list(lexer)
    except ValueError:
        return None


def parse(command: str, root: str) -> Request | Rejected:
    """Return the single request *command* asks for, scoped to the tenant *root*."""
    tokens = tokenize(command)
    if not tokens:
        return Rejected("empty command, unbalanced quotes, or control characters")
    statements = _split_statements(tokens)
    if statements is None:
        return Rejected("shell syntax is not allowed")
    if len(statements) > 1:
        return _destroy_chain(statements, root)
    return _statement(statements[0], root)


def _split_statements(tokens: list[str]) -> list[list[str]] | None:
    statements: list[list[str]] = [[]]
    for token in tokens:
        if token == ";":
            statements.append([])
        else:
            statements[-1].append(token)
    if len(statements) > 1 and not statements[-1]:
        statements.pop()  # syncoid ends some chains with "; "
    if any(not statement for statement in statements):
        return None
    return statements


def _statement(tokens: list[str], root: str) -> Request | Rejected:
    if tokens[0] == "sudo":
        return Rejected("sudo is not allowed; run syncoid with --no-privilege-elevation")
    redirected = tokens[-3:] == _REDIRECT and tokens[:2] == ["zfs", "receive"]
    body = tokens[:-3] if redirected else tokens
    if any(set(token) <= _PUNCTUATION for token in body):
        return Rejected("shell syntax is not allowed")
    handler = _HANDLERS.get((body[0], body[1])) if len(body) > 1 else None
    if handler is not None:
        return handler(body[2:], root)
    return _probe(body, root)


def _probe(tokens: list[str], root: str) -> Request | Rejected:
    if tokens in _NO_ARGS_PROBES:
        return Reply(0)
    if tokens[:2] == ["command", "-v"] and len(tokens) == 3:  # noqa: PLR2004
        if _PROBED_COMMAND.fullmatch(tokens[2]):
            return Reply(1)
    if tokens[:-1] == _POOL_FEATURE_PROBE and tokens[-1] == names.pool_of(root):
        return Run("zpool", tuple(tokens[1:]))
    return Rejected("command not allowed")


def _outside(name: str, root: str) -> Rejected:
    return Rejected(f"{name!r} is not a dataset inside {root}")


def _get(args: list[str], root: str) -> Request | Rejected:
    if not args or tuple(args[:-1]) not in _GET_FORMS:
        return Rejected("only the zfs get forms syncoid uses are allowed; use zfs list")
    if not names.in_scope(root, args[-1]):
        return _outside(args[-1], root)
    return Run("zfs", ("get", *args))


def _receive(args: list[str], root: str) -> Request | Rejected:
    if not args:
        return Rejected("zfs receive needs a target dataset")
    *flags, dataset = args
    if not names.strictly_below(root, dataset):
        return _outside(dataset, root)
    if flags == ["-A"]:
        return Run("zfs", ("receive", "-A", dataset))
    if not set(flags) <= {"-s", "-F", "-u"} or len(set(flags)) != len(flags):
        return Rejected("zfs receive only accepts -s, -F, -u, or -A")
    return Receive(dataset=dataset, resumable="-s" in flags)


def _destroy(args: list[str], root: str) -> Request | Rejected:
    if not args:
        return Rejected("zfs destroy needs a target")
    *flags, target = args
    if "@" in target:
        return _destroy_snapshots(flags, target, root)
    if flags not in ([], ["-r"]):
        return Rejected("destroying a dataset only accepts -r")
    if not names.strictly_below(root, target):
        return _outside(target, root)
    return Run("zfs", ("destroy", *flags, target))


def _destroy_snapshots(flags: list[str], target: str, root: str) -> Request | Rejected:
    if not set(flags) <= {"-d", "-r"} or len(set(flags)) != len(flags):
        return Rejected("destroying snapshots only accepts -d and -r")
    dataset, _, snapshots = target.partition("@")
    if not names.strictly_below(root, dataset):
        return _outside(dataset, root)
    if not all(_snapshot_item(item) for item in snapshots.split(",")):
        return Rejected(f"invalid snapshot list {snapshots!r}")
    recursive = ("-r",) if "-r" in flags else ()
    return Run("zfs", ("destroy", "-d", *recursive, target))


def _snapshot_item(item: str) -> bool:
    if names.is_snapshot_name(item):
        return True
    match = _SNAPSHOT_RANGE.fullmatch(item)
    return match is not None and all(
        not part or names.is_snapshot_name(part) for part in match.groups()
    )


def _destroy_chain(statements: list[list[str]], root: str) -> Request | Rejected:
    targets: list[str] = []
    for statement in statements:
        if len(statement) != 3 or statement[:2] != ["zfs", "destroy"] or "@" not in statement[2]:  # noqa: PLR2004
            return Rejected("only chains of 'zfs destroy dataset@snapshot' are allowed")
        targets.append(statement[2])
    datasets = {target.partition("@")[0] for target in targets}
    if len(datasets) != 1:
        return Rejected("a destroy chain must name a single dataset")
    snapshots = ",".join(target.partition("@")[2] for target in targets)
    return _destroy_snapshots([], f"{datasets.pop()}@{snapshots}", root)


def _create(args: list[str], root: str) -> Request | Rejected:
    if not args:
        return Rejected("zfs create needs a dataset")
    *flags, dataset = args
    if flags not in ([], ["-p"]):
        return Rejected("zfs create only accepts -p")
    if not names.strictly_below(root, dataset):
        return _outside(dataset, root)
    return Run("zfs", ("create", *flags, dataset))


def _csv_within(allowed: frozenset[str]) -> Callable[[str], bool]:
    return lambda value: all(part in allowed for part in value.split(","))


_LIST_OPTIONS: dict[str, Callable[[str], bool]] = {
    "-d": lambda value: _DEPTH.fullmatch(value) is not None,
    "-t": _csv_within(_LIST_TYPES),
    "-o": _csv_within(_LIST_COLUMNS),
    "-s": lambda value: value in _LIST_COLUMNS,
    "-S": lambda value: value in _LIST_COLUMNS,
}


def _list(args: list[str], root: str) -> Request | Rejected:
    built: list[str] = []
    dataset = root
    rest = list(args)
    while rest:
        token = rest.pop(0)
        if _LIST_SWITCHES.fullmatch(token):
            built.append(token)
        elif token in _LIST_OPTIONS and rest:
            value = rest.pop(0)
            if not _LIST_OPTIONS[token](value):
                return Rejected(f"invalid value {value!r} for zfs list {token}")
            built += [token, value]
        elif not rest and not token.startswith("-"):
            dataset = token
        else:
            return Rejected(f"zfs list option {token!r} is not allowed")
    if not names.in_scope(root, dataset):
        return _outside(dataset, root)
    return Run("zfs", ("list", *built, dataset))


def _send(args: list[str], root: str) -> Request | Rejected:
    if len(args) == 2 and args[0] == "-t":  # noqa: PLR2004
        if _RESUME_TOKEN.fullmatch(args[1]) is None:
            return Rejected("invalid resume token")
        return ResumeSend(args[1])
    if not args:
        return Rejected("zfs send needs a snapshot")
    *options, target = args
    parts = names.split_snapshot(target)
    if parts is None or not names.in_scope(root, parts[0]):
        return _outside(target, root)
    built: list[str] = []
    rest = list(options)
    while rest:
        token = rest.pop(0)
        if _SEND_SWITCHES.fullmatch(token):
            built.append(token)
        elif token in {"-i", "-I"} and rest:
            origin = rest.pop(0)
            if not _origin_of(origin, parts[0]):
                return Rejected(f"incremental origin {origin!r} must be a snapshot of {parts[0]}")
            built += [token, origin]
        else:
            return Rejected(f"zfs send option {token!r} is not allowed")
    return Run("zfs", ("send", *built, target))


def _origin_of(origin: str, dataset: str) -> bool:
    if origin.startswith("@"):
        return names.is_snapshot_name(origin[1:])
    parts = names.split_snapshot(origin)
    return parts is not None and parts[0] == dataset


_HANDLERS: dict[tuple[str, str], Callable[[list[str], str], Request | Rejected]] = {
    ("zfs", "get"): _get,
    ("zfs", "receive"): _receive,
    ("zfs", "destroy"): _destroy,
    ("zfs", "create"): _create,
    ("zfs", "list"): _list,
    ("zfs", "send"): _send,
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `uv run pytest tests/test_grammar.py -q`
Expected: PASS.

- [ ] **Step 5: Lint and commit**

Run: `just lint` and fix any findings without weakening validation.

```bash
git add -A
git commit -m "Parse forced SSH commands into requests scoped to the tenant root"
```

---

### Task 3: Runner and gate execution

**Files:**
- Create: `src/zfs_tenant/zfs.py`, `src/zfs_tenant/gate.py`
- Test: `tests/test_gate.py`

**Interfaces:**
- Consumes: `grammar.parse`, request dataclasses, `names.*`.
- Produces:
  - `zfs.CommandError(argv: Sequence[str], status: int, stderr: str)` with attributes `argv`, `status`, `stderr`.
  - `zfs.Runner = Callable[[Sequence[str]], str]`; `zfs.run(argv: Sequence[str]) -> str`; `zfs.does_not_exist(error: CommandError) -> bool`.
  - `gate.DENIED_STATUS = 126`; `gate.GateConfig(root: str, zfs: str = "zfs", zpool: str = "zpool", require_encryption: bool = True)`; `gate.Spawner` protocol `(argv: Sequence[str], *, merge_stderr: bool) -> int`; `gate.Effects(runner, spawner, log, write_error)`; `gate.handle(command: str | None, config: GateConfig, effects: Effects | None = None) -> int`.

- [ ] **Step 1: Write the failing gate tests**

`tests/test_gate.py`:

```python
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
        if not queue:
            return ""
        item = queue.pop(0)
        if isinstance(item, zfs.CommandError):
            raise item
        return item

    def spawner(self, argv: Sequence[str], *, merge_stderr: bool) -> int:
        self.spawns.append((tuple(argv), merge_stderr))
        return self.spawn_status

    def effects(self) -> gate.Effects:
        return gate.Effects(
            runner=self.runner,
            spawner=self.spawner,
            log=self.logs.append,
            write_error=self.errors.append,
        )


def test_interactive_session_is_denied() -> None:
    fake = Fake()
    assert gate.handle(None, CONFIG, fake.effects()) == gate.DENIED_STATUS
    assert fake.errors == ["zfs-tenant: interactive sessions are not allowed"]
    assert not fake.spawns


def test_rejected_command_runs_nothing() -> None:
    fake = Fake()
    assert gate.handle("reboot", CONFIG, fake.effects()) == gate.DENIED_STATUS
    assert fake.errors == ["zfs-tenant: command not allowed: command not allowed"]
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
    assert fake.spawns == [((ZFS, "receive", "-u", "-s", DS), True)]


def test_new_plaintext_dataset_is_destroyed() -> None:
    fake = Fake(outputs={LIST_ENCRYPTION: [MISSING, f"{DS}\toff\n{DS}/child\toff\n"]})
    assert gate.handle(f"zfs receive {DS}", CONFIG, fake.effects()) == 1
    assert (ZFS, "destroy", "-r", DS) in fake.runs
    assert (ZFS, "destroy", "-r", f"{DS}/child") not in fake.runs
    assert fake.errors == [f"zfs-tenant: refused unencrypted dataset {DS}; send raw (zfs send -w)"]


def test_new_plaintext_child_under_encrypted_dataset_is_destroyed() -> None:
    before = f"{DS}\taes-256-gcm\n"
    after = f"{DS}\taes-256-gcm\n{DS}/child\toff\n"
    fake = Fake(outputs={LIST_ENCRYPTION: [before, after]})
    assert gate.handle(f"zfs receive {DS}", CONFIG, fake.effects()) == 1
    assert (ZFS, "destroy", "-r", f"{DS}/child") in fake.runs
    assert (ZFS, "destroy", "-r", DS) not in fake.runs


def test_existing_plaintext_target_is_refused_before_reading_the_stream() -> None:
    fake = Fake(outputs={LIST_ENCRYPTION: [f"{DS}\toff\n"]})
    assert gate.handle(f"zfs receive {DS}", CONFIG, fake.effects()) == 1
    assert not fake.spawns
    assert "unencrypted" in fake.errors[0]


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
    assert gate.handle(f"zfs send -t {TOKEN}", CONFIG, fake.effects()) == gate.DENIED_STATUS
    assert not fake.spawns


def test_unreadable_resume_token_fails() -> None:
    error = zfs.CommandError((ZFS, "send"), 255, "invalid token\n")
    fake = Fake(outputs={(ZFS, "send", "-nvP", "-t", TOKEN): [error]})
    assert gate.handle(f"zfs send -t {TOKEN}", CONFIG, fake.effects()) == 1
    assert not fake.spawns
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `uv run pytest tests/test_gate.py -q`
Expected: FAIL with `ImportError: cannot import name 'gate'`.

- [ ] **Step 3: Implement `src/zfs_tenant/zfs.py`**

```python
"""Run zfs and zpool with captured output."""

from __future__ import annotations

import subprocess
from collections.abc import Callable, Sequence

Runner = Callable[[Sequence[str]], str]


class CommandError(RuntimeError):
    """A command exited with a non-zero status."""

    def __init__(self, argv: Sequence[str], status: int, stderr: str) -> None:
        """Remember the failed command, its status, and its stderr."""
        self.argv = tuple(argv)
        self.status = status
        self.stderr = stderr
        super().__init__(f"{' '.join(self.argv)} exited {status}: {stderr.strip()}")


def run(argv: Sequence[str]) -> str:
    """Run *argv* without a shell and return stdout; raise CommandError on failure."""
    result = subprocess.run(list(argv), capture_output=True, text=True, check=False)  # noqa: S603 - argv is built by this package
    if result.returncode != 0:
        raise CommandError(argv, result.returncode, result.stderr)
    return result.stdout


def does_not_exist(error: CommandError) -> bool:
    """Return whether *error* is zfs reporting a missing dataset."""
    return "does not exist" in error.stderr
```

- [ ] **Step 4: Implement `src/zfs_tenant/gate.py`**

```python
"""Execute one allowed request as the tenant user."""

from __future__ import annotations

import re
import subprocess
import sys
import syslog
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Protocol

from zfs_tenant import grammar, names, zfs

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

DENIED_STATUS = 126
_TONAME = re.compile(r"^\s*toname = (\S+)\s*$", re.MULTILINE)


@dataclass(frozen=True)
class GateConfig:
    """The tenant root and the binaries the gate may run."""

    root: str
    zfs: str = "zfs"
    zpool: str = "zpool"
    require_encryption: bool = True


class Spawner(Protocol):
    """Run a command attached to the SSH session and return its exit status."""

    def __call__(self, argv: Sequence[str], *, merge_stderr: bool) -> int:
        """Run *argv*; with *merge_stderr*, send its stderr to stdout."""


def spawn(argv: Sequence[str], *, merge_stderr: bool) -> int:
    """Run *argv* with the session's stdin and stdout and return its exit status."""
    stderr = subprocess.STDOUT if merge_stderr else None
    return subprocess.run(list(argv), stderr=stderr, check=False).returncode  # noqa: S603 - argv comes from grammar.parse


def log_to_syslog(message: str) -> None:
    """Record one gate decision in the auth log."""
    syslog.openlog("zfs-tenant", syslog.LOG_PID, syslog.LOG_AUTH)
    syslog.syslog(syslog.LOG_INFO, message)


def write_stderr(message: str) -> None:
    """Print *message* for the SSH client."""
    sys.stderr.write(message + "\n")


@dataclass(frozen=True)
class Effects:
    """Side effects the gate needs; tests replace them."""

    runner: zfs.Runner = zfs.run
    spawner: Spawner = spawn
    log: Callable[[str], None] = log_to_syslog
    write_error: Callable[[str], None] = field(default=write_stderr)


def handle(command: str | None, config: GateConfig, effects: Effects | None = None) -> int:
    """Parse and execute *command*, returning the exit status for the SSH session."""
    fx = effects or Effects()
    if command is None:
        fx.log(f"root={config.root} denied interactive session")
        fx.write_error("zfs-tenant: interactive sessions are not allowed")
        return DENIED_STATUS
    request = grammar.parse(command, config.root)
    if isinstance(request, grammar.Rejected):
        fx.log(f"root={config.root} denied {command!r}: {request.reason}")
        fx.write_error(f"zfs-tenant: command not allowed: {request.reason}")
        return DENIED_STATUS
    fx.log(f"root={config.root} allowed {command!r}")
    try:
        return _execute(request, config, fx)
    except zfs.CommandError as error:
        fx.write_error(f"zfs-tenant: {error}")
        return 1


def _execute(request: grammar.Request, config: GateConfig, fx: Effects) -> int:
    if isinstance(request, grammar.Reply):
        return request.status
    if isinstance(request, grammar.Run):
        binary = config.zfs if request.program == "zfs" else config.zpool
        return fx.spawner([binary, *request.args], merge_stderr=False)
    if isinstance(request, grammar.ResumeSend):
        return _resume_send(request.token, config, fx)
    return _receive(request, config, fx)


def _resume_send(token: str, config: GateConfig, fx: Effects) -> int:
    described = fx.runner([config.zfs, "send", "-nvP", "-t", token])
    match = _TONAME.search(described)
    parts = names.split_snapshot(match.group(1)) if match else None
    if parts is None or not names.in_scope(config.root, parts[0]):
        fx.write_error("zfs-tenant: resume token does not name a snapshot inside the tenant root")
        return DENIED_STATUS
    return fx.spawner([config.zfs, "send", "-t", token], merge_stderr=False)


def _receive(request: grammar.Receive, config: GateConfig, fx: Effects) -> int:
    before: dict[str, str] = {}
    if config.require_encryption:
        before = _encryption(request.dataset, config, fx)
        if before.get(request.dataset) == "off":
            fx.write_error(
                f"zfs-tenant: {request.dataset} is unencrypted; "
                "this host only accepts raw encrypted sends (zfs send -w)"
            )
            return 1
    argv = [config.zfs, "receive", "-u"]
    if request.resumable:
        argv.append("-s")
    argv.append(request.dataset)
    status = fx.spawner(argv, merge_stderr=True)
    if status != 0 or not config.require_encryption:
        return status
    after = _encryption(request.dataset, config, fx)
    plain = sorted(
        name for name, encryption in after.items() if encryption == "off" and name not in before
    )
    if not plain:
        return 0
    for name in _topmost(plain):
        fx.runner([config.zfs, "destroy", "-r", name])
        fx.write_error(f"zfs-tenant: refused unencrypted dataset {name}; send raw (zfs send -w)")
    return 1


def _encryption(dataset: str, config: GateConfig, fx: Effects) -> dict[str, str]:
    argv = [config.zfs, "list", "-H", "-r", "-t", "filesystem,volume", "-o", "name,encryption"]
    try:
        output = fx.runner([*argv, dataset])
    except zfs.CommandError as error:
        if zfs.does_not_exist(error):
            return {}
        raise
    rows = (line.split("\t") for line in output.splitlines() if line)
    return {name: encryption for name, encryption in rows}


def _topmost(datasets: list[str]) -> list[str]:
    return [
        name for name in datasets if not any(name.startswith(other + "/") for other in datasets)
    ]
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `uv run pytest tests/test_gate.py -q`
Expected: PASS.

- [ ] **Step 6: Lint and commit**

Run: `just lint`.

```bash
git add -A
git commit -m "Execute gate requests and refuse unencrypted datasets"
```

---

### Task 4: Tenant setup

**Files:**
- Create: `src/zfs_tenant/setup.py`
- Test: `tests/test_setup.py`

**Interfaces:**
- Consumes: `zfs.Runner`, `names.*`.
- Produces: `setup.TenantSpec(root: str, user: str, quota: str, reservation: str | None = None, filesystem_limit: int = 100, snapshot_limit: int = 20000)`, `setup.SetupError`, `setup.validate(spec) -> None`, `setup.commands(spec) -> list[list[str]]` (zfs arguments without the binary), `setup.apply(spec: TenantSpec, *, zfs_path: str, zpool_path: str, runner: zfs.Runner) -> None`.

- [ ] **Step 1: Write the failing setup tests**

`tests/test_setup.py`:

```python
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
            "sharenfs=off",
            "sharesmb=off",
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
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `uv run pytest tests/test_setup.py -q`
Expected: FAIL with `ImportError: cannot import name 'setup'`.

- [ ] **Step 3: Implement `src/zfs_tenant/setup.py`**

```python
"""Create a tenant root, lock down its properties, and delegate it, idempotently."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING

from zfs_tenant import names

if TYPE_CHECKING:
    from zfs_tenant.zfs import Runner

FIXED_PROPERTIES = (
    "mountpoint=none",
    "canmount=off",
    "readonly=on",
    "exec=off",
    "setuid=off",
    "devices=off",
    "volmode=none",
    "sharenfs=off",
    "sharesmb=off",
)
LOCAL_PERMISSIONS = "create,mount,receive"
DESCENDANT_PERMISSIONS = "create,destroy,mount,receive,send"

_SIZE = re.compile(r"[0-9]+(?:\.[0-9]+)?[KMGTPE]?")
_USER = re.compile(r"[a-z_][a-z0-9_-]{0,31}")


class SetupError(RuntimeError):
    """The tenant cannot be set up as requested."""


@dataclass(frozen=True)
class TenantSpec:
    """One tenant root and the limits it gets."""

    root: str
    user: str
    quota: str
    reservation: str | None = None
    filesystem_limit: int = 100
    snapshot_limit: int = 20000


def validate(spec: TenantSpec) -> None:
    """Raise SetupError unless *spec* is safe to turn into zfs commands."""
    if not names.is_dataset(spec.root) or "/" not in spec.root:
        msg = f"root must be a dataset below a pool, got {spec.root!r}"
        raise SetupError(msg)
    if _USER.fullmatch(spec.user) is None:
        msg = f"invalid user name {spec.user!r}"
        raise SetupError(msg)
    for label, size in (("quota", spec.quota), ("reservation", spec.reservation)):
        if size is not None and _SIZE.fullmatch(size) is None:
            msg = f"invalid {label} {size!r}; use a size such as 500G or 2T"
            raise SetupError(msg)
    if spec.filesystem_limit < 1 or spec.snapshot_limit < 1:
        msg = "filesystem and snapshot limits must be positive"
        raise SetupError(msg)


def commands(spec: TenantSpec) -> list[list[str]]:
    """Return the zfs argument lists that bring the tenant root to the desired state."""
    properties = [
        f"quota={spec.quota}",
        f"reservation={spec.reservation or 'none'}",
        f"filesystem_limit={spec.filesystem_limit}",
        f"snapshot_limit={spec.snapshot_limit}",
        *FIXED_PROPERTIES,
    ]
    return [
        ["create", "-p", spec.root],
        ["set", *properties, spec.root],
        ["unallow", "-u", spec.user, spec.root],
        ["allow", "-l", "-u", spec.user, LOCAL_PERMISSIONS, spec.root],
        ["allow", "-d", "-u", spec.user, DESCENDANT_PERMISSIONS, spec.root],
    ]


def apply(spec: TenantSpec, *, zfs_path: str, zpool_path: str, runner: Runner) -> None:
    """Validate *spec*, check the pool supports limits, and run every setup command."""
    validate(spec)
    pool = names.pool_of(spec.root)
    feature = runner(
        [zpool_path, "get", "-H", "-o", "value", "feature@filesystem_limits", pool]
    ).strip()
    if feature not in {"enabled", "active"}:
        msg = (
            f"pool {pool} has feature@filesystem_limits={feature or 'unknown'}; "
            f"enable it with: zpool set feature@filesystem_limits=enabled {pool}"
        )
        raise SetupError(msg)
    for args in commands(spec):
        runner([zfs_path, *args])
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `uv run pytest tests/test_setup.py -q`
Expected: PASS.

- [ ] **Step 5: Lint and commit**

Run: `just lint`.

```bash
git add -A
git commit -m "Set up tenant roots with locked-down properties and scoped delegation"
```

---

### Task 5: Grace-period sweep

**Files:**
- Create: `src/zfs_tenant/sweep.py`
- Test: `tests/test_sweep.py`

**Interfaces:**
- Consumes: `zfs.Runner`, `zfs.CommandError`, `zfs.does_not_exist`.
- Produces: `sweep.DEFAULT_TAG = "zfs-tenant-grace"`, `sweep.SweepResult(held: list[str], released: list[str])`, `sweep.sweep(roots: Sequence[str], *, grace_days: float, tag: str, zfs_path: str, runner: zfs.Runner, now: float) -> SweepResult`.

- [ ] **Step 1: Write the failing sweep tests**

`tests/test_sweep.py`:

```python
"""Tests for grace-period holds."""

from __future__ import annotations

from typing import TYPE_CHECKING

from zfs_tenant import sweep, zfs

if TYPE_CHECKING:
    from collections.abc import Sequence

ROOT = "tank/friends/joe"
ZFS = "/sbin/zfs"
TAG = sweep.DEFAULT_TAG
DAY = 86400
NOW = 100 * DAY
LIST = (ZFS, "list", "-H", "-p", "-r", "-t", "snapshot", "-o", "name,creation,defer_destroy", ROOT)


class FakeZfs:
    def __init__(self, snapshots: str, holds: str) -> None:
        self.snapshots = snapshots
        self.holds = holds
        self.calls: list[tuple[str, ...]] = []
        self.missing: set[str] = set()

    def __call__(self, argv: Sequence[str]) -> str:
        call = tuple(argv)
        self.calls.append(call)
        if call == LIST:
            return self.snapshots
        if call[1] == "holds":
            return self.holds
        if call[1] == "hold" and any(name in self.missing for name in call[3:]):
            raise zfs.CommandError(call, 1, "cannot hold snapshot: dataset does not exist\n")
        return ""

    def mutations(self, verb: str) -> list[tuple[str, ...]]:
        return [call for call in self.calls if call[1] == verb]


SNAPSHOTS = "\n".join(
    [
        f"{ROOT}/a@s1\t{10 * DAY}\toff",
        f"{ROOT}/a@s2\t{20 * DAY}\toff",
        f"{ROOT}/a@s3\t{90 * DAY}\ton",
        f"{ROOT}/b@t1\t{30 * DAY}\toff",
        f"{ROOT}/b@%recv\t{95 * DAY}\toff",
        "",
    ]
)


def test_holds_newest_live_snapshot_and_releases_expired_holds() -> None:
    holds = f"{ROOT}/a@s1\t{TAG}\t{80 * DAY}\n{ROOT}/b@t1\tother\t{1 * DAY}\n"
    fake = FakeZfs(SNAPSHOTS, holds)
    result = sweep.sweep([ROOT], grace_days=14, tag=TAG, zfs_path=ZFS, runner=fake, now=NOW)
    assert result.released == [f"{ROOT}/a@s1"]
    assert result.held == [f"{ROOT}/a@s2", f"{ROOT}/b@t1"]
    assert fake.mutations("release") == [(ZFS, "release", TAG, f"{ROOT}/a@s1")]
    assert fake.mutations("hold") == [(ZFS, "hold", TAG, f"{ROOT}/a@s2", f"{ROOT}/b@t1")]


def test_fresh_holds_are_kept_and_not_duplicated() -> None:
    holds = f"{ROOT}/a@s2\t{TAG}\t{95 * DAY}\n{ROOT}/b@t1\t{TAG}\t{99 * DAY}\n"
    fake = FakeZfs(SNAPSHOTS, holds)
    result = sweep.sweep([ROOT], grace_days=14, tag=TAG, zfs_path=ZFS, runner=fake, now=NOW)
    assert result.held == []
    assert result.released == []
    assert fake.mutations("hold") == []


def test_zero_grace_releases_everything_and_rehold_newest() -> None:
    holds = f"{ROOT}/a@s2\t{TAG}\t{NOW}\n"
    fake = FakeZfs(SNAPSHOTS, holds)
    result = sweep.sweep([ROOT], grace_days=0, tag=TAG, zfs_path=ZFS, runner=fake, now=NOW)
    assert result.released == [f"{ROOT}/a@s2"]
    assert f"{ROOT}/a@s2" in result.held


def test_in_progress_receives_are_ignored() -> None:
    fake = FakeZfs(SNAPSHOTS, "")
    sweep.sweep([ROOT], grace_days=14, tag=TAG, zfs_path=ZFS, runner=fake, now=NOW)
    holds_query = next(call for call in fake.calls if call[1] == "holds")
    assert f"{ROOT}/b@%recv" not in holds_query


def test_a_snapshot_destroyed_mid_sweep_does_not_abort() -> None:
    fake = FakeZfs(SNAPSHOTS, "")
    fake.missing = {f"{ROOT}/a@s2"}
    result = sweep.sweep([ROOT], grace_days=14, tag=TAG, zfs_path=ZFS, runner=fake, now=NOW)
    assert result.held == [f"{ROOT}/b@t1"]


def test_empty_root_runs_no_hold_queries() -> None:
    fake = FakeZfs("", "")
    result = sweep.sweep([ROOT], grace_days=14, tag=TAG, zfs_path=ZFS, runner=fake, now=NOW)
    assert result == sweep.SweepResult(held=[], released=[])
    assert fake.calls == [LIST]
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `uv run pytest tests/test_sweep.py -q`
Expected: FAIL with `ImportError: cannot import name 'sweep'`.

- [ ] **Step 3: Implement `src/zfs_tenant/sweep.py`**

```python
"""Hold each dataset's newest snapshot and release holds older than the grace period.

Tenants cannot release holds, so whatever a compromised sender deletes, every dataset
keeps one restore point per day of the grace period. Snapshots a tenant destroys with
``zfs destroy -d`` disappear when their hold is released.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from zfs_tenant import zfs

if TYPE_CHECKING:
    from collections.abc import Iterator, Sequence

DEFAULT_TAG = "zfs-tenant-grace"
_CHUNK = 256
_SECONDS_PER_DAY = 86400


@dataclass(frozen=True)
class _Snapshot:
    name: str
    creation: int
    deferred: bool

    @property
    def dataset(self) -> str:
        return self.name.partition("@")[0]


@dataclass
class SweepResult:
    """Snapshots that got a new hold and snapshots whose hold was released."""

    held: list[str] = field(default_factory=list)
    released: list[str] = field(default_factory=list)


def sweep(
    roots: Sequence[str],
    *,
    grace_days: float,
    tag: str,
    zfs_path: str,
    runner: zfs.Runner,
    now: float,
) -> SweepResult:
    """Release expired *tag* holds under *roots*, then hold each dataset's newest snapshot."""
    result = SweepResult()
    cutoff = now - grace_days * _SECONDS_PER_DAY
    for root in roots:
        snapshots = _snapshots(root, zfs_path, runner)
        holds = _holds([snapshot.name for snapshot in snapshots], tag, zfs_path, runner)
        expired = [name for name, stamp in holds.items() if stamp <= cutoff]
        _apply(runner, [zfs_path, "release", tag], expired)
        kept = set(holds) - set(expired)
        wanted = [snap.name for snap in _newest_live(snapshots) if snap.name not in kept]
        result.held += _apply(runner, [zfs_path, "hold", tag], wanted)
        result.released += expired
    return result


def _snapshots(root: str, zfs_path: str, runner: zfs.Runner) -> list[_Snapshot]:
    output = runner(
        [
            zfs_path,
            "list",
            "-H",
            "-p",
            "-r",
            "-t",
            "snapshot",
            "-o",
            "name,creation,defer_destroy",
            root,
        ]
    )
    snapshots = []
    for line in output.splitlines():
        if not line:
            continue
        name, creation, deferred = line.split("\t")
        if "%" not in name:  # in-progress receives
            snapshots.append(_Snapshot(name, int(creation), deferred == "on"))
    return snapshots


def _holds(snapshots: list[str], tag: str, zfs_path: str, runner: zfs.Runner) -> dict[str, int]:
    holds: dict[str, int] = {}
    for chunk in _chunks(snapshots):
        for line in runner([zfs_path, "holds", "-H", "-p", *chunk]).splitlines():
            if not line:
                continue
            name, hold_tag, stamp = line.split("\t")
            if hold_tag == tag:
                holds[name] = int(stamp)
    return holds


def _newest_live(snapshots: list[_Snapshot]) -> list[_Snapshot]:
    newest: dict[str, _Snapshot] = {}
    for snapshot in snapshots:
        if snapshot.deferred:
            continue
        current = newest.get(snapshot.dataset)
        if current is None or snapshot.creation >= current.creation:
            newest[snapshot.dataset] = snapshot
    return list(newest.values())


def _apply(runner: zfs.Runner, prefix: list[str], snapshots: list[str]) -> list[str]:
    """Run *prefix* on *snapshots* in chunks; skip snapshots destroyed meanwhile."""
    done: list[str] = []
    for chunk in _chunks(snapshots):
        try:
            runner([*prefix, *chunk])
            done += chunk
        except zfs.CommandError as error:
            if not zfs.does_not_exist(error):
                raise
            for name in chunk:
                try:
                    runner([*prefix, name])
                    done.append(name)
                except zfs.CommandError as single:
                    if not zfs.does_not_exist(single):
                        raise
    return done


def _chunks(items: list[str]) -> Iterator[list[str]]:
    for start in range(0, len(items), _CHUNK):
        yield items[start : start + _CHUNK]
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `uv run pytest tests/test_sweep.py -q`
Expected: PASS.

- [ ] **Step 5: Lint and commit**

Run: `just lint`.

```bash
git add -A
git commit -m "Keep daily grace-period holds on tenant snapshots"
```

---

### Task 6: Command-line interface

**Files:**
- Create: `src/zfs_tenant/cli.py`
- Test: `tests/test_cli.py`

**Interfaces:**
- Consumes: `gate.handle`, `gate.GateConfig`, `setup.*`, `sweep.*`, `zfs.run`, `names.*`.
- Produces: `cli.main(argv: Sequence[str] | None = None) -> int` with subcommands `gate`, `setup`, `sweep`, `authorized-key` and `--version`.

- [ ] **Step 1: Write the failing CLI tests**

`tests/test_cli.py`:

```python
"""Tests for the zfs-tenant command line."""

from __future__ import annotations

import os
import subprocess
import sys
from typing import TYPE_CHECKING

import pytest

from zfs_tenant import __version__, cli, zfs

if TYPE_CHECKING:
    from collections.abc import Sequence
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
    fake: Path, command: str | None, stdin: bytes = b""
) -> subprocess.CompletedProcess[bytes]:
    env = {key: value for key, value in os.environ.items() if key != "SSH_ORIGINAL_COMMAND"}
    if command is not None:
        env["SSH_ORIGINAL_COMMAND"] = command
    argv = [sys.executable, "-m", "zfs_tenant", "gate", "--root", ROOT]
    argv += ["--zfs", str(fake), "--zpool", str(fake), "--no-require-encryption"]
    return subprocess.run(argv, input=stdin, capture_output=True, env=env, check=False)


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


def test_sweep_prints_what_it_did(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def fake_run(argv: Sequence[str]) -> str:
        if argv[1] == "list":
            return f"{ROOT}/a@s1\t100\toff\n"
        return ""

    monkeypatch.setattr(zfs, "run", fake_run)
    assert cli.main(["sweep", "--root", ROOT, "--grace-days", "14"]) == 0
    assert capsys.readouterr().out == f"held {ROOT}/a@s1\n"


def test_version(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exit_info:
        cli.main(["--version"])
    assert exit_info.value.code == 0
    assert __version__ in capsys.readouterr().out
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `uv run pytest tests/test_cli.py -q`
Expected: FAIL with `ModuleNotFoundError: No module named 'zfs_tenant.cli'`.

- [ ] **Step 3: Implement `src/zfs_tenant/cli.py`**

```python
"""Command line: the SSH gate, tenant setup, the grace-period sweep, and key lines."""

from __future__ import annotations

import argparse
import os
import shlex
import sys
import time
from typing import TYPE_CHECKING

from zfs_tenant import __version__, gate, names, setup, sweep, zfs

if TYPE_CHECKING:
    from collections.abc import Sequence

USAGE_STATUS = 2


def main(argv: Sequence[str] | None = None) -> int:
    """Run the zfs-tenant command line and return its exit status."""
    args = _parser().parse_args(argv)
    status: int = args.handler(args)
    return status


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="zfs-tenant",
        description="Give a friend a quota-capped corner of your ZFS pool for raw encrypted backups.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    commands = parser.add_subparsers(required=True, metavar="COMMAND")

    gate_parser = commands.add_parser(
        "gate", help="SSH forced command: run one allowed zfs command from SSH_ORIGINAL_COMMAND"
    )
    gate_parser.add_argument("--root", required=True, help="tenant root dataset")
    gate_parser.add_argument("--zfs", default="zfs", help="path to zfs")
    gate_parser.add_argument("--zpool", default="zpool", help="path to zpool")
    gate_parser.add_argument(
        "--no-require-encryption",
        action="store_true",
        help="accept unencrypted datasets (by default only raw encrypted sends are kept)",
    )
    gate_parser.set_defaults(handler=_gate)

    setup_parser = commands.add_parser(
        "setup", help="create the tenant root, set its properties, and delegate it (run as root)"
    )
    setup_parser.add_argument("--root", required=True, help="tenant root dataset")
    setup_parser.add_argument("--user", required=True, help="local user the tenant logs in as")
    setup_parser.add_argument("--quota", required=True, help="size cap, e.g. 2T")
    setup_parser.add_argument("--reservation", help="guaranteed space, e.g. 2T")
    setup_parser.add_argument("--filesystem-limit", type=int, default=100)
    setup_parser.add_argument("--snapshot-limit", type=int, default=20000)
    setup_parser.add_argument("--zfs", default="zfs", help="path to zfs")
    setup_parser.add_argument("--zpool", default="zpool", help="path to zpool")
    setup_parser.add_argument(
        "--dry-run", action="store_true", help="print the commands instead of running them"
    )
    setup_parser.set_defaults(handler=_setup)

    sweep_parser = commands.add_parser(
        "sweep", help="hold each dataset's newest snapshot and release expired holds (run as root)"
    )
    sweep_parser.add_argument("--root", action="append", required=True, help="tenant root; repeat")
    sweep_parser.add_argument("--grace-days", type=float, required=True)
    sweep_parser.add_argument("--tag", default=sweep.DEFAULT_TAG)
    sweep_parser.add_argument("--zfs", default="zfs", help="path to zfs")
    sweep_parser.set_defaults(handler=_sweep)

    key_parser = commands.add_parser(
        "authorized-key", help="print an authorized_keys line that forces the gate"
    )
    key_parser.add_argument("--gate-command", required=True, help="full gate command line")
    key_parser.add_argument(
        "--from", dest="sources", required=True, help="allowed source addresses"
    )
    key_parser.add_argument("key", nargs="+", help="the tenant's public key")
    key_parser.set_defaults(handler=_authorized_key)
    return parser


def _fail(message: str, status: int = 1) -> int:
    sys.stderr.write(f"zfs-tenant: {message}\n")
    return status


def _gate(args: argparse.Namespace) -> int:
    if not names.is_dataset(args.root) or "/" not in args.root:
        return _fail(f"--root must be a dataset below a pool, got {args.root!r}", USAGE_STATUS)
    config = gate.GateConfig(
        root=args.root,
        zfs=args.zfs,
        zpool=args.zpool,
        require_encryption=not args.no_require_encryption,
    )
    return gate.handle(os.environ.get("SSH_ORIGINAL_COMMAND"), config)


def _setup(args: argparse.Namespace) -> int:
    spec = setup.TenantSpec(
        root=args.root,
        user=args.user,
        quota=args.quota,
        reservation=args.reservation,
        filesystem_limit=args.filesystem_limit,
        snapshot_limit=args.snapshot_limit,
    )
    try:
        if args.dry_run:
            setup.validate(spec)
            for command in setup.commands(spec):
                sys.stdout.write(shlex.join([args.zfs, *command]) + "\n")
            return 0
        setup.apply(spec, zfs_path=args.zfs, zpool_path=args.zpool, runner=zfs.run)
    except (setup.SetupError, zfs.CommandError) as error:
        return _fail(str(error))
    sys.stdout.write(f"zfs-tenant: {spec.root} is ready for {spec.user}\n")
    return 0


def _sweep(args: argparse.Namespace) -> int:
    try:
        result = sweep.sweep(
            args.root,
            grace_days=args.grace_days,
            tag=args.tag,
            zfs_path=args.zfs,
            runner=zfs.run,
            now=time.time(),
        )
    except zfs.CommandError as error:
        return _fail(str(error))
    for name in result.released:
        sys.stdout.write(f"released {name}\n")
    for name in result.held:
        sys.stdout.write(f"held {name}\n")
    return 0


def _authorized_key(args: argparse.Namespace) -> int:
    key = " ".join(args.key)
    fields = (args.gate_command, args.sources, key)
    if any('"' in value or "\n" in value or "\r" in value for value in fields):
        return _fail(
            "the gate command, sources, and key must not contain quotes or newlines", USAGE_STATUS
        )
    sys.stdout.write(f'restrict,from="{args.sources}",command="{args.gate_command}" {key}\n')
    return 0
```

Note: `zfs.run` is looked up at call time (`runner=zfs.run` inside the handlers), which is what lets `test_sweep_prints_what_it_did` monkeypatch it.

- [ ] **Step 4: Run the full unit suite**

Run: `uv run pytest -n auto -q`
Expected: PASS (all tests in `tests/`).

- [ ] **Step 5: Build and smoke-test the zipapp**

Run: `just pyz`
Expected: prints `zfs-tenant <version>`.

- [ ] **Step 6: Lint and commit**

Run: `just lint`.

```bash
git add -A
git commit -m "Add the gate, setup, sweep, and authorized-key commands"
```

---

### Task 7: Nix package and NixOS modules

**Files:**
- Create: `flake.nix`, `nix/host-module.nix`, `nix/sender-module.nix`
- Generate: `flake.lock` (via `nix flake lock`)

**Interfaces:**
- Consumes: the `zfs-tenant` console script.
- Produces: `packages.<system>.default`; `nixosModules.host` (alias `default`), `nixosModules.sender`; `checks.<system>.package`, `checks.<system>.modules`; options exactly as below.

- [ ] **Step 1: Write `nix/host-module.nix`**

```nix
# Host side: give each tenant a quota-capped dataset they can only reach through the gate.
{
  config,
  lib,
  pkgs,
  ...
}:

let
  cfg = config.services.zfs-tenant;

  zfsBin = lib.getExe' cfg.zfsPackage "zfs";
  zpoolBin = lib.getExe' cfg.zfsPackage "zpool";
  tenantBin = lib.getExe cfg.package;

  hasLineBreak = value: lib.hasInfix "\n" value || lib.hasInfix "\r" value;
  safeFromPattern = pattern: !hasLineBreak pattern && !lib.hasInfix "\"" pattern && !lib.hasInfix "," pattern;
  safeAuthorizedKey = key: !hasLineBreak key;
  safeTenantName = name: builtins.match "[a-z][a-z0-9-]{0,20}" name != null;
  safeDatasetName =
    dataset:
    builtins.match "[A-Za-z0-9_.:-]+(/[A-Za-z0-9_.:-]+)+" dataset != null
    && lib.all (segment: segment != "." && segment != ".." && !lib.hasPrefix "-" segment) (
      lib.splitString "/" dataset
    );

  gateCommand =
    tenant:
    lib.concatStringsSep " " (
      [
        tenantBin
        "gate"
        "--root"
        tenant.dataset
        "--zfs"
        zfsBin
        "--zpool"
        zpoolBin
      ]
      ++ lib.optional (!tenant.requireEncryption) "--no-require-encryption"
    );

  forcedCommandKey =
    tenant: key:
    ''restrict,from="${lib.concatStringsSep "," tenant.allowedFrom}",command="${gateCommand tenant}" ${key}'';

  roots = lib.mapAttrsToList (_: tenant: tenant.dataset) cfg.tenants;
  nestedRoots = lib.any (outer: lib.any (inner: lib.hasPrefix "${outer}/" inner) roots) roots;

  tenantModule =
    { name, ... }:
    {
      options = {
        dataset = lib.mkOption {
          type = lib.types.str;
          example = "tank/friends/joe";
          description = "Tenant root dataset. Created if missing; the tenant can only work below it.";
        };
        user = lib.mkOption {
          type = lib.types.str;
          default = "zfs-tenant-${name}";
          defaultText = lib.literalExpression ''"zfs-tenant-<name>"'';
          description = "Local system user the tenant logs in as.";
        };
        quota = lib.mkOption {
          type = lib.types.str;
          example = "2T";
          description = "Hard cap on everything below the tenant root, snapshots included.";
        };
        reservation = lib.mkOption {
          type = lib.types.nullOr lib.types.str;
          default = null;
          example = "2T";
          description = ''
            Space guaranteed to the tenant. Setting it to the quota also hides how full the
            host pool is, because `available` then never drops below the unused quota.
          '';
        };
        filesystemLimit = lib.mkOption {
          type = lib.types.ints.positive;
          default = 100;
          description = "Maximum number of datasets below the tenant root.";
        };
        snapshotLimit = lib.mkOption {
          type = lib.types.ints.positive;
          default = 20000;
          description = "Maximum number of snapshots below the tenant root.";
        };
        requireEncryption = lib.mkOption {
          type = lib.types.bool;
          default = true;
          description = "Destroy newly received datasets that are not encrypted (tenants must send raw).";
        };
        authorizedKeys = lib.mkOption {
          type = lib.types.listOf lib.types.singleLineStr;
          default = [ ];
          example = [ "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA... joe@nas" ];
          description = "Public keys that may reach the gate for this tenant.";
        };
        allowedFrom = lib.mkOption {
          type = lib.types.listOf lib.types.str;
          default = [ ];
          example = [ "100.64.0.12" ];
          description = "authorized_keys from= patterns, e.g. the tenant's tailnet address.";
        };
      };
    };
in
{
  options.services.zfs-tenant = {
    enable = lib.mkEnableOption "zfs-tenant: quota-capped ZFS datasets for friends' raw encrypted backups";

    package = lib.mkOption {
      type = lib.types.package;
      description = "Package providing the zfs-tenant executable. The flake module sets it.";
    };

    zfsPackage = lib.mkOption {
      type = lib.types.package;
      default = config.boot.zfs.package;
      defaultText = lib.literalExpression "config.boot.zfs.package";
      description = "Package providing zfs and zpool.";
    };

    graceDays = lib.mkOption {
      type = lib.types.nullOr lib.types.ints.unsigned;
      default = 14;
      description = ''
        Keep a hold on every dataset's newest snapshot each day and release holds after this many
        days, so a compromised tenant machine cannot delete recent restore points. null disables it.
      '';
    };

    sweepOnCalendar = lib.mkOption {
      type = lib.types.str;
      default = "daily";
      description = "systemd calendar expression for the grace-period sweep.";
    };

    tenants = lib.mkOption {
      type = lib.types.attrsOf (lib.types.submodule tenantModule);
      default = { };
      description = "Tenants keyed by a short name.";
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion = config.services.openssh.enable;
        message = "services.zfs-tenant requires services.openssh.enable = true.";
      }
      {
        assertion = !nestedRoots && lib.length roots == lib.length (lib.unique roots);
        message = "services.zfs-tenant.tenants datasets must be distinct and must not contain each other.";
      }
    ]
    ++ lib.concatLists (
      lib.mapAttrsToList (name: tenant: [
        {
          assertion = safeTenantName name;
          message = "services.zfs-tenant.tenants.${name}: names must match [a-z][a-z0-9-]{0,20}.";
        }
        {
          assertion = safeDatasetName tenant.dataset;
          message = "services.zfs-tenant.tenants.${name}.dataset must be a safe dataset below a pool.";
        }
        {
          assertion = tenant.authorizedKeys != [ ] && lib.all safeAuthorizedKey tenant.authorizedKeys;
          message = "services.zfs-tenant.tenants.${name}.authorizedKeys must list at least one single-line key.";
        }
        {
          assertion = tenant.allowedFrom != [ ] && lib.all safeFromPattern tenant.allowedFrom;
          message = "services.zfs-tenant.tenants.${name}.allowedFrom must list patterns without quotes, commas, or newlines.";
        }
      ]) cfg.tenants
    );

    environment.systemPackages = [ cfg.package ];

    users.groups.zfs-tenant = { };

    users.users = lib.mapAttrs' (
      _: tenant:
      lib.nameValuePair tenant.user {
        isSystemUser = true;
        group = "zfs-tenant";
        home = "/var/empty";
        # sshd runs the forced command through the login shell.
        shell = pkgs.runtimeShell;
        openssh.authorizedKeys.keys = map (forcedCommandKey tenant) tenant.authorizedKeys;
      }
    ) cfg.tenants;

    systemd.services =
      lib.mapAttrs' (
        name: tenant:
        lib.nameValuePair "zfs-tenant-setup-${name}" {
          description = "Set up the zfs-tenant root for ${name}";
          wantedBy = [ "multi-user.target" ];
          wants = [ "zfs.target" ];
          after = [ "zfs.target" ];
          # Delegation is pool state, so reapply it on every boot and rebuild.
          serviceConfig = {
            Type = "oneshot";
            RemainAfterExit = true;
            ExecStart = lib.escapeShellArgs (
              [
                tenantBin
                "setup"
                "--root"
                tenant.dataset
                "--user"
                tenant.user
                "--quota"
                tenant.quota
                "--filesystem-limit"
                (toString tenant.filesystemLimit)
                "--snapshot-limit"
                (toString tenant.snapshotLimit)
                "--zfs"
                zfsBin
                "--zpool"
                zpoolBin
              ]
              ++ lib.optionals (tenant.reservation != null) [
                "--reservation"
                tenant.reservation
              ]
            );
          };
        }
      ) cfg.tenants
      // lib.optionalAttrs (cfg.graceDays != null && cfg.tenants != { }) {
        zfs-tenant-sweep = {
          description = "Grace-period holds on zfs-tenant snapshots";
          wants = [ "zfs.target" ];
          after = [ "zfs.target" ];
          serviceConfig = {
            Type = "oneshot";
            ExecStart = lib.escapeShellArgs (
              [
                tenantBin
                "sweep"
                "--grace-days"
                (toString cfg.graceDays)
                "--zfs"
                zfsBin
              ]
              ++ lib.concatMap (root: [
                "--root"
                root
              ]) roots
            );
          };
        };
      };

    systemd.timers = lib.optionalAttrs (cfg.graceDays != null && cfg.tenants != { }) {
      zfs-tenant-sweep = {
        wantedBy = [ "timers.target" ];
        timerConfig = {
          OnCalendar = cfg.sweepOnCalendar;
          Persistent = true;
          RandomizedDelaySec = "30m";
        };
      };
    };
  };
}
```

- [ ] **Step 2: Write `nix/sender-module.nix`**

```nix
# Sender side: push sanoid snapshots to friends with syncoid, as a user that can only `zfs send`.
{
  config,
  lib,
  pkgs,
  ...
}:

let
  cfg = config.services.zfs-tenant-sender;

  sources = lib.unique (lib.concatMap (target: lib.attrNames target.datasets) (lib.attrValues cfg.targets));

  knownHostsFile = name: "/etc/zfs-tenant-sender/${name}.known_hosts";

  syncoidArgs =
    name: target:
    [
      # The syncoid user is not root and holds only `zfs send`; syncoid 2.3.0 pastes the
      # receiver's resume token into a local shell, so this also bounds a malicious host.
      "--no-privilege-elevation"
      "--no-sync-snap"
      "--sendoptions=w"
      "--compress=none"
      "--sshkey=${target.sshKey}"
      "--sshport=${toString target.port}"
      "--sshoption=UserKnownHostsFile=${knownHostsFile name}"
      "--sshoption=StrictHostKeyChecking=yes"
      "--sshoption=BatchMode=yes"
      "--sshoption=IdentitiesOnly=yes"
    ]
    ++ lib.optional target.recursive "--recursive"
    ++ lib.optional target.deleteTargetSnapshots "--delete-target-snapshots"
    ++ target.extraArgs;

  pushScript =
    name: target:
    pkgs.writeShellScript "zfs-tenant-push-${name}" ''
      set -u
      status=0
      ${lib.concatMapStringsSep "\n" (
        source:
        "syncoid ${lib.escapeShellArgs (syncoidArgs name target)} ${lib.escapeShellArg source} ${
          lib.escapeShellArg "${target.user}@${target.host}:${target.datasets.${source}}"
        } || status=1"
      ) (lib.attrNames target.datasets)}
      exit "$status"
    '';

  targetModule = {
    options = {
      host = lib.mkOption {
        type = lib.types.str;
        example = "bas-nas";
        description = "Host running the zfs-tenant gate (tailnet name or address).";
      };
      user = lib.mkOption {
        type = lib.types.str;
        example = "zfs-tenant-joe";
        description = "Tenant user on that host.";
      };
      port = lib.mkOption {
        type = lib.types.port;
        default = 22;
        description = "SSH port on the host.";
      };
      sshKey = lib.mkOption {
        type = lib.types.str;
        example = "/var/lib/zfs-tenant-sender/id_ed25519";
        description = "Private key readable by the zfs-tenant-sender user. Keep it out of the Nix store.";
      };
      knownHosts = lib.mkOption {
        type = lib.types.lines;
        example = "bas-nas ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA...";
        description = "known_hosts lines pinning the host key; the push refuses anything else.";
      };
      datasets = lib.mkOption {
        type = lib.types.attrsOf lib.types.str;
        example = {
          "tank/offsite" = "tank/friends/joe/offsite";
        };
        description = "Local dataset to target dataset below your tenant root. Send encrypted datasets only.";
      };
      recursive = lib.mkOption {
        type = lib.types.bool;
        default = true;
        description = "Also push child datasets.";
      };
      deleteTargetSnapshots = lib.mkOption {
        type = lib.types.bool;
        default = true;
        description = "Mirror your snapshot retention on the host (deletions wait for the host's grace period).";
      };
      onCalendar = lib.mkOption {
        type = lib.types.str;
        default = "daily";
        description = "systemd calendar expression for the push.";
      };
      extraArgs = lib.mkOption {
        type = lib.types.listOf lib.types.str;
        default = [ ];
        description = "Extra syncoid arguments.";
      };
    };
  };
in
{
  options.services.zfs-tenant-sender = {
    enable = lib.mkEnableOption "syncoid pushes to zfs-tenant hosts";

    zfsPackage = lib.mkOption {
      type = lib.types.package;
      default = config.boot.zfs.package;
      defaultText = lib.literalExpression "config.boot.zfs.package";
      description = "Package providing zfs.";
    };

    sanoidPackage = lib.mkOption {
      type = lib.types.package;
      default = pkgs.sanoid;
      defaultText = lib.literalExpression "pkgs.sanoid";
      description = "Package providing syncoid.";
    };

    targets = lib.mkOption {
      type = lib.types.attrsOf (lib.types.submodule targetModule);
      default = { };
      description = "Hosts to push to, keyed by a short name.";
    };
  };

  config = lib.mkIf cfg.enable {
    users.groups.zfs-tenant-sender = { };
    users.users.zfs-tenant-sender = {
      isSystemUser = true;
      group = "zfs-tenant-sender";
      home = "/var/lib/zfs-tenant-sender";
      createHome = true;
    };

    environment.etc = lib.mapAttrs' (
      name: target: lib.nameValuePair "zfs-tenant-sender/${name}.known_hosts" { text = target.knownHosts; }
    ) cfg.targets;

    systemd.services = {
      zfs-tenant-sender-delegate = {
        description = "Delegate zfs send to the zfs-tenant-sender user";
        wantedBy = [ "multi-user.target" ];
        wants = [ "zfs.target" ];
        after = [ "zfs.target" ];
        path = [ cfg.zfsPackage ];
        # Delegation is pool state, so reapply it on every boot and rebuild.
        script = lib.concatMapStringsSep "\n" (
          source: "zfs allow -u zfs-tenant-sender send ${lib.escapeShellArg source}"
        ) sources;
        serviceConfig = {
          Type = "oneshot";
          RemainAfterExit = true;
        };
      };
    }
    // lib.mapAttrs' (
      name: target:
      lib.nameValuePair "zfs-tenant-push-${name}" {
        description = "Push snapshots to ${target.host} with syncoid";
        wants = [ "network-online.target" ];
        after = [
          "network-online.target"
          "zfs-tenant-sender-delegate.service"
        ];
        path = [
          cfg.sanoidPackage
          cfg.zfsPackage
          pkgs.mbuffer
          pkgs.openssh
          pkgs.procps
        ];
        serviceConfig = {
          Type = "oneshot";
          User = "zfs-tenant-sender";
          Group = "zfs-tenant-sender";
          ExecStart = pushScript name target;
          NoNewPrivileges = true;
          PrivateTmp = true;
          ProtectHome = true;
          ProtectSystem = "strict";
        };
      }
    ) cfg.targets;

    systemd.timers = lib.mapAttrs' (
      name: target:
      lib.nameValuePair "zfs-tenant-push-${name}" {
        wantedBy = [ "timers.target" ];
        timerConfig = {
          OnCalendar = target.onCalendar;
          Persistent = true;
          RandomizedDelaySec = "15m";
        };
      }
    ) cfg.targets;
  };
}
```

- [ ] **Step 3: Write `flake.nix`**

```nix
{
  description = "Give a friend a quota-capped corner of your ZFS pool for raw encrypted backups";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs =
    { self, nixpkgs }:
    let
      lib = nixpkgs.lib;
      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];
      forAllSystems = lib.genAttrs systems;
      version = "0.0.0+${builtins.substring 0 8 (self.lastModifiedDate or "19700101")}";

      mkPackage =
        pkgs:
        pkgs.python3Packages.buildPythonApplication {
          pname = "zfs-tenant";
          inherit version;
          pyproject = true;
          src = self;
          build-system = with pkgs.python3Packages; [
            hatchling
            hatch-vcs
          ];
          env.SETUPTOOLS_SCM_PRETEND_VERSION = version;
          nativeCheckInputs = [ pkgs.python3Packages.pytestCheckHook ];
          pythonImportsCheck = [ "zfs_tenant" ];
          meta = {
            description = "Give a friend a quota-capped corner of your ZFS pool for raw encrypted backups";
            homepage = "https://github.com/basnijholt/zfs-tenant";
            license = lib.licenses.mit;
            mainProgram = "zfs-tenant";
            platforms = lib.platforms.linux;
          };
        };

      evalModules =
        system: extra:
        lib.nixosSystem {
          inherit system;
          modules = [
            self.nixosModules.host
            self.nixosModules.sender
            {
              system.stateVersion = "26.05";
              boot.loader.grub.enable = false;
              fileSystems."/" = {
                device = "none";
                fsType = "tmpfs";
              };
              services.openssh.enable = true;
            }
            extra
          ];
        };

      exampleTenant = {
        services.zfs-tenant = {
          enable = true;
          tenants.joe = {
            dataset = "tank/friends/joe";
            quota = "2T";
            authorizedKeys = [ "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestOnlyKey joe" ];
            allowedFrom = [ "100.64.0.12" ];
          };
        };
        services.zfs-tenant-sender = {
          enable = true;
          targets.bas = {
            host = "bas-nas";
            user = "zfs-tenant-joe";
            sshKey = "/var/lib/zfs-tenant-sender/id_ed25519";
            knownHosts = "bas-nas ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestOnlyHostKey";
            datasets."tank/offsite" = "tank/friends/joe/offsite";
          };
        };
      };

      failedAssertions = eval: builtins.filter (a: !a.assertion) eval.config.assertions;
    in
    {
      packages = forAllSystems (system: {
        default = mkPackage nixpkgs.legacyPackages.${system};
      });

      nixosModules = {
        default = self.nixosModules.host;
        host =
          { lib, pkgs, ... }:
          {
            imports = [ ./nix/host-module.nix ];
            services.zfs-tenant.package = lib.mkDefault self.packages.${pkgs.stdenv.hostPlatform.system}.default;
          };
        sender = ./nix/sender-module.nix;
      };

      checks = forAllSystems (
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
          good = evalModules system exampleTenant;
          nested = evalModules system (
            lib.recursiveUpdate exampleTenant {
              services.zfs-tenant.tenants.sub = {
                dataset = "tank/friends/joe/sub";
                quota = "1T";
                authorizedKeys = [ "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestOnlyKey sub" ];
                allowedFrom = [ "100.64.0.13" ];
              };
            }
          );
          goodFailures = failedAssertions good;
          keys = good.config.users.users.zfs-tenant-joe.openssh.authorizedKeys.keys;
          keyLine = builtins.head keys;
        in
        {
          package = self.packages.${system}.default;
          modules =
            assert goodFailures == [ ] || throw (lib.concatMapStringsSep "\n" (a: a.message) goodFailures);
            assert failedAssertions nested != [ ];
            assert lib.hasPrefix ''restrict,from="100.64.0.12",command="'' keyLine;
            assert lib.hasInfix " gate --root tank/friends/joe --zfs " keyLine;
            assert good.config.systemd.services ? zfs-tenant-setup-joe;
            assert good.config.systemd.timers ? zfs-tenant-sweep;
            assert good.config.systemd.services.zfs-tenant-push-bas.serviceConfig.User == "zfs-tenant-sender";
            pkgs.runCommand "zfs-tenant-module-check" { } "touch $out";
        }
      );
    };
}
```

- [ ] **Step 4: Lock and check**

Run: `nix flake lock && nix flake check -L`
Expected: the package builds with its unit tests passing (pytestCheckHook) and `checks.*.modules` passes. `git add` new files first: flakes only see tracked files.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "Package zfs-tenant with Nix and add host and sender NixOS modules"
```

---

### Task 8: Two-node VM integration test

**Files:**
- Create: `nix/integration-test.nix`, `nix/integration/client_key`, `nix/integration/client_key.pub`, `nix/integration/host_key`, `nix/integration/host_key.pub`, `nix/integration/README.md`
- Modify: `flake.nix` (add `checks.x86_64-linux.integration`)

**Interfaces:**
- Consumes: `nixosModules.host`, `nixosModules.sender`, `packages.x86_64-linux.default`.
- Produces: `checks.x86_64-linux.integration`.

- [ ] **Step 1: Generate throwaway keys**

```bash
mkdir -p nix/integration
ssh-keygen -q -t ed25519 -N '' -C zfs-tenant-test-client -f nix/integration/client_key
ssh-keygen -q -t ed25519 -N '' -C zfs-tenant-test-host -f nix/integration/host_key
```

`nix/integration/README.md`:

```markdown
# Throwaway test keys

These keys exist only for the NixOS VM test in `../integration-test.nix`.
They authenticate ephemeral VMs and protect nothing real.
```

- [ ] **Step 2: Write `nix/integration-test.nix`**

```nix
# Two NixOS VMs with real OpenZFS: `sender` pushes with real syncoid through real sshd into
# the gate on `host`. Proves the grammar matches syncoid 2.3.0 and that the delegation,
# quota, encryption policy, and grace holds behave as the README promises.
{
  pkgs,
  hostModule,
  senderModule,
}:
let
  hostPublicKey = pkgs.lib.strings.trim (builtins.readFile ./integration/host_key.pub);
  clientPublicKey = pkgs.lib.strings.trim (builtins.readFile ./integration/client_key.pub);
  zfsNode = {
    boot.supportedFilesystems = [ "zfs" ];
    networking.hostId = "deadbeef";
    virtualisation.emptyDiskImages = [ 1024 ];
    virtualisation.memorySize = 2048;
  };
in
pkgs.testers.runNixOSTest {
  name = "zfs-tenant-integration";

  nodes.host =
    { nodes, ... }:
    {
      imports = [
        hostModule
        zfsNode
      ];
      services.openssh = {
        enable = true;
        hostKeys = [
          {
            path = "/etc/ssh/ssh_host_ed25519_key";
            type = "ed25519";
          }
        ];
      };
      environment.etc."ssh/ssh_host_ed25519_key" = {
        source = ./integration/host_key;
        mode = "0600";
      };
      services.zfs-tenant = {
        enable = true;
        tenants.joe = {
          dataset = "tank/friends/joe";
          quota = "256M";
          authorizedKeys = [ clientPublicKey ];
          allowedFrom = [ nodes.sender.networking.primaryIPAddress ];
        };
      };
    };

  nodes.sender =
    { ... }:
    {
      imports = [
        senderModule
        zfsNode
      ];
      environment.etc."zfs-tenant-sender/id_ed25519" = {
        source = ./integration/client_key;
        mode = "0400";
        user = "zfs-tenant-sender";
      };
      services.zfs-tenant-sender = {
        enable = true;
        targets.host = {
          host = "host";
          user = "zfs-tenant-joe";
          sshKey = "/etc/zfs-tenant-sender/id_ed25519";
          knownHosts = "host ${hostPublicKey}";
          datasets."src/offsite" = "tank/friends/joe/offsite";
        };
      };
    };

  testScript = ''
    import shlex

    gate = (
        "ssh -T -i /etc/zfs-tenant-sender/id_ed25519 -o IdentitiesOnly=yes -o BatchMode=yes "
        "-o UserKnownHostsFile=/etc/zfs-tenant-sender/host.known_hosts "
        "-o StrictHostKeyChecking=yes zfs-tenant-joe@host"
    )

    def via_gate(command):
        return f"{gate} {shlex.quote(command)}"

    def snapshots(dataset):
        return host.succeed(f"zfs list -H -o name -t snapshot -r {dataset}")

    start_all()
    host.wait_for_unit("sshd.service")
    sender.wait_for_unit("multi-user.target")

    with subtest("pools, datasets, and delegation exist"):
        host.succeed("zpool create -f -O mountpoint=none tank /dev/vdb")
        host.succeed("zfs create -o mountpoint=/srv/host tank/host")
        host.succeed("echo host-secret > /srv/host/secret")
        host.succeed("systemctl restart zfs-tenant-setup-joe.service")
        sender.succeed("zpool create -f -O mountpoint=/src src /dev/vdb")
        sender.succeed("printf correcthorsebatterystaple > /root/pp")
        sender.succeed(
            "zfs create -o encryption=on -o keyformat=passphrase "
            "-o keylocation=file:///root/pp src/offsite"
        )
        sender.succeed("zfs create src/offsite/photos && zfs create src/offsite/docs")
        sender.succeed("head -c 2M /dev/urandom > /src/offsite/photos/a.jpg")
        sender.succeed("head -c 4M /dev/urandom > /src/offsite/docs/b.pdf")
        sender.succeed("zfs snapshot -r src/offsite@autosnap_1")
        sender.succeed("systemctl restart zfs-tenant-sender-delegate.service")

    with subtest("setup locks down the tenant root and is idempotent"):
        props = host.succeed(
            "zfs get -H -o property,value quota,mountpoint,readonly,volmode,filesystem_limit "
            "tank/friends/joe"
        )
        for expected in ["quota\t256M", "mountpoint\tnone", "readonly\ton", "volmode\tnone"]:
            assert expected in props, props
        allow = host.succeed("zfs allow tank/friends/joe")
        assert "user zfs-tenant-joe create,mount,receive" in allow, allow
        assert "user zfs-tenant-joe create,destroy,mount,receive,send" in allow, allow
        host.succeed("systemctl restart zfs-tenant-setup-joe.service")

    with subtest("syncoid pushes raw encrypted datasets through the gate"):
        sender.succeed("systemctl start zfs-tenant-push-host.service")
        assert "tank/friends/joe/offsite/photos@autosnap_1" in snapshots("tank/friends/joe")
        keystatus = host.succeed("zfs get -H -o value keystatus tank/friends/joe/offsite/photos")
        assert keystatus.strip() == "unavailable", keystatus
        sender.succeed("zfs snapshot -r src/offsite@autosnap_2")
        sender.succeed("systemctl start zfs-tenant-push-host.service")
        assert "tank/friends/joe/offsite/docs@autosnap_2" in snapshots("tank/friends/joe")

    with subtest("the host never mounts tenant data"):
        host.succeed("zfs mount -a")
        assert "friends" not in host.succeed("mount")

    with subtest("the tenant sees only its own subtree"):
        listing = sender.succeed(via_gate("zfs list -H -o name -r"))
        assert "tank/friends/joe/offsite" in listing, listing
        assert "tank/host" not in listing, listing
        for command in [
            "zfs list -r tank",
            "zfs get -H name tank/host",
            "sudo zfs get -H name tank/friends/joe",
            "cat /etc/passwd",
            "reboot",
            "zfs destroy tank/friends/joe",
            "zfs destroy -r tank/host",
        ]:
            out = sender.fail(via_gate(command) + " 2>&1")
            assert "command not allowed" in out, (command, out)
        out = sender.fail(f"{gate} 2>&1 </dev/null")
        assert "interactive sessions are not allowed" in out, out
        host.succeed("test -e /srv/host/secret")

    with subtest("the kernel denies the tenant user outside its subtree"):
        host.fail("su zfs-tenant-joe -s /bin/sh -c 'zfs destroy tank/friends/joe'")
        host.fail("su zfs-tenant-joe -s /bin/sh -c 'zfs set quota=none tank/friends/joe'")
        host.fail("su zfs-tenant-joe -s /bin/sh -c 'zfs destroy tank/host'")

    with subtest("plaintext streams are refused and removed"):
        sender.succeed("zfs create -o encryption=off src/plain && echo hi > /src/plain/x")
        sender.succeed("zfs snapshot src/plain@s1")
        out = sender.fail(
            "zfs send src/plain@s1 | " + via_gate("zfs receive tank/friends/joe/plain") + " 2>&1"
        )
        assert "refused unencrypted dataset tank/friends/joe/plain" in out, out
        host.fail("zfs list tank/friends/joe/plain")

    with subtest("an interrupted receive resumes"):
        sender.fail(
            "zfs send -w src/offsite/docs@autosnap_2 | head -c 1000000 | "
            + via_gate("zfs receive -s tank/friends/joe/resume")
        )
        row = sender.succeed(via_gate("zfs get -H receive_resume_token tank/friends/joe/resume"))
        token = row.split("\t")[2]
        assert token not in ("", "-"), row
        sender.succeed(f"zfs send -t {token} | " + via_gate("zfs receive -s tank/friends/joe/resume"))
        encryption = host.succeed("zfs get -H -o value encryption tank/friends/joe/resume")
        assert encryption.strip() != "off", encryption

    with subtest("pruning is deferred on held snapshots and the sweep finishes it"):
        host.succeed("zfs-tenant sweep --root tank/friends/joe --grace-days 14")
        held = host.succeed("zfs holds -H tank/friends/joe/offsite/photos@autosnap_2")
        assert "zfs-tenant-grace" in held, held
        sender.succeed("zfs snapshot -r src/offsite@autosnap_3")
        sender.succeed("systemctl start zfs-tenant-push-host.service")
        sender.succeed("zfs destroy -r src/offsite@autosnap_2")
        sender.succeed("systemctl start zfs-tenant-push-host.service")
        deferred = host.succeed(
            "zfs get -H -o value defer_destroy tank/friends/joe/offsite/photos@autosnap_2"
        )
        assert deferred.strip() == "on", deferred
        host.succeed("zfs-tenant sweep --root tank/friends/joe --grace-days 0")
        host.fail("zfs list tank/friends/joe/offsite/photos@autosnap_2")
        held = host.succeed("zfs holds -H tank/friends/joe/offsite/photos@autosnap_3")
        assert "zfs-tenant-grace" in held, held

    with subtest("held snapshots survive a compromised tenant"):
        sender.fail(via_gate("zfs destroy -r tank/friends/joe/offsite/photos"))
        assert "autosnap_3" in snapshots("tank/friends/joe/offsite/photos")
        host.fail(
            "su zfs-tenant-joe -s /bin/sh -c "
            "'zfs release zfs-tenant-grace tank/friends/joe/offsite/photos@autosnap_3'"
        )

    with subtest("a restore through the gate decrypts on the sender"):
        sender.succeed(
            via_gate("zfs send -w tank/friends/joe/offsite/docs@autosnap_3")
            + " | zfs receive -u src/restored"
        )
        sender.succeed("zfs load-key -L file:///root/pp src/restored")
        sender.succeed("zfs set mountpoint=/restored src/restored && zfs mount src/restored")
        sender.succeed("cmp /restored/b.pdf /src/offsite/docs/b.pdf")

    with subtest("an interrupted restore resumes through the gate"):
        sender.fail(
            via_gate("zfs send -w tank/friends/joe/offsite/docs@autosnap_3")
            + " | head -c 1000000 | zfs receive -s -u src/restored-docs"
        )
        token = sender.succeed(
            "zfs get -H -o value receive_resume_token src/restored-docs"
        ).strip()
        sender.succeed(via_gate(f"zfs send -t {token}") + " | zfs receive -s -u src/restored-docs")
        sender.fail(via_gate("zfs send -t 1-0-0-0"))

    with subtest("the quota caps what the tenant can store"):
        sender.succeed("zfs create src/offsite/big")
        sender.succeed("head -c 300M /dev/urandom > /src/offsite/big/blob")
        sender.succeed("zfs snapshot src/offsite/big@autosnap_4")
        out = sender.fail(
            "zfs send -w src/offsite/big@autosnap_4 | "
            + via_gate("zfs receive tank/friends/joe/offsite/big")
            + " 2>&1"
        )
        assert "quota exceeded" in out, out
  '';
}
```

- [ ] **Step 3: Wire the check into `flake.nix`**

In the `checks` attribute set, merge the integration test for `x86_64-linux` only:

```nix
        }
        // lib.optionalAttrs (system == "x86_64-linux") {
          integration = import ./nix/integration-test.nix {
            inherit pkgs;
            hostModule = self.nixosModules.host;
            senderModule = self.nixosModules.sender;
          };
        }
```

placed so the `checks` function returns `{ package = ...; modules = ...; } // lib.optionalAttrs ...`.

- [ ] **Step 4: Run the VM test**

Run: `git add -A && just vm-test`
Expected: all subtests pass. When a subtest fails, fix the root cause in the gate, grammar, or modules (e.g. a syncoid command shape the grammar rejects shows up as `zfs-tenant: command not allowed` in the push service journal: `sender.succeed("journalctl -u zfs-tenant-push-host")`), add a matching unit test, and rerun. Never weaken a security assertion to make it pass.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "Test syncoid pushes, restores, quota, and grace holds in NixOS VMs"
```

---

### Task 9: README, logo, and agent guidelines

**Files:**
- Create: `README.md`, `docs/logo.svg`, `CLAUDE.md`, symlinks `AGENTS.md -> CLAUDE.md`, `GEMINI.md -> CLAUDE.md`

- [ ] **Step 1: Write `docs/logo.svg`**

An animated 240x240 tile in the pytest-shm style: a dark rounded tile; a pool drawn as a wide rounded container split into compartments; the host compartments are grey and dim; the tenant compartment has an amber outline, a padlock, and a fill level that rises to a dashed quota line and stops there; the word `zfs-tenant` below with `-tenant` in amber; animations disabled under `prefers-reduced-motion`. Include `<title>` and `<desc>`.

- [ ] **Step 2: Write `README.md`**

Sections, in this order, following the pytest-shm README format (badges, right-aligned logo, `[!NOTE]` summary, doctoc TOC markers):

1. Why: the friend-to-friend story; why the old VM + iSCSI setup is no longer needed (`zfs allow`).
2. How it works: mermaid diagram (sender with sanoid and syncoid, tailnet, sshd forced command, gate, delegated tenant root); the "kernel is the jail, the gate removes the shell" sentence.
3. Security model: the guarantees table from the spec; "What it cannot hide" (metadata, host can delete); residual risks including the syncoid resume-token issue and the sender-side mitigation.
4. Quick start on NixOS: host module example, sender module example, generating the sender key, tailnet ACL note (allow only the sender's node to reach port 22 on the host).
5. Manual setup (TrueNAS SCALE or any Linux): download `zfs-tenant.pyz` from the latest release, create a user, `zfs-tenant setup --dry-run` then run it as root, `zfs-tenant authorized-key` to produce the key line, persistence notes (delegation lives in the pool; keep the `.pyz` on a pool dataset).
6. Pushing with syncoid by hand: the exact flag set and why each flag is there.
7. Restoring: `ssh ... zfs send -w ... | zfs receive`, resuming with `zfs send -t`, `zfs load-key` on the sender.
8. Removing datasets and the grace period: `zfs destroy -d dataset@%`, then `zfs destroy -r dataset` after the grace period.
9. What the gate allows: a table of accepted commands.
10. FAQ: why not a container or VM (kernel check by uid, `/dev/zfs`), why not zrepl, why not pull, why Python and not Bash.
11. Development: `just install`, `just test`, `just lint`, `just vm-test`, `just pyz`.
12. License.

- [ ] **Step 3: Write `CLAUDE.md`**

Same structure as pytest-shm's `CLAUDE.md` (core principles KISS/YAGNI/DRY, architecture tree of `src/zfs_tenant/`, key design decisions: kernel delegation is the boundary, grammar is pure and never shells out, stdlib only for the `.pyz`, encryption policy never destroys pre-existing datasets, deferred destroys plus grace holds; development commands table; testing notes about the fake-effects unit tests and the VM test; git safety; PR rules; releases via `gh release create`). Then `ln -s CLAUDE.md AGENTS.md && ln -s CLAUDE.md GEMINI.md`.

- [ ] **Step 4: Commit**

```bash
git add -A
git commit -m "Document the design, setup paths, and security model; add the logo"
```

---

### Task 10: CI, release workflows, and publishing the repository

**Files:**
- Create: `.github/workflows/ci.yml`, `.github/workflows/release.yml`, `.github/workflows/release-drafter.yml`, `.github/workflows/toc.yaml`, `.github/release-drafter.yml`, `.github/renovate.json`

- [ ] **Step 1: Write `.github/workflows/ci.yml`**

```yaml
name: CI

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  test:
    runs-on: ubuntu-latest
    strategy:
      fail-fast: false
      matrix:
        python-version: ["3.10", "3.11", "3.12", "3.13", "3.14"]
    steps:
      - uses: actions/checkout@v6
      - name: Install uv
        uses: astral-sh/setup-uv@v7
      - name: Set up Python ${{ matrix.python-version }}
        run: uv python install ${{ matrix.python-version }}
      - name: Install dependencies
        run: uv sync --dev --python ${{ matrix.python-version }}
      - name: Run tests
        run: uv run --python ${{ matrix.python-version }} pytest -n auto -v

  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
      - name: Install uv
        uses: astral-sh/setup-uv@v7
      - name: Set up Python
        run: uv python install 3.14
      - name: Install dependencies
        run: uv sync --dev
      - name: Run pre-commit (via prek)
        uses: j178/prek-action@v1

  pyz:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
        with:
          fetch-depth: 0
      - name: Install uv
        uses: astral-sh/setup-uv@v7
      - name: Install just
        uses: extractions/setup-just@v3
      - name: Build and smoke-test the zipapp
        run: just pyz

  nix:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
      # Expose /dev/kvm to the Nix build users before the daemon starts, so the NixOS VM
      # test runs with hardware acceleration instead of TCG emulation.
      - name: Enable KVM for VM tests
        run: |
          echo 'KERNEL=="kvm", GROUP="kvm", MODE="0666", OPTIONS+="static_node=kvm"' \
            | sudo tee /etc/udev/rules.d/99-kvm4all.rules
          sudo udevadm control --reload-rules
          sudo udevadm trigger --name-match=kvm
      - name: Install Nix
        uses: cachix/install-nix-action@v31
        with:
          extra_nix_config: |
            system-features = nixos-test benchmark big-parallel kvm
      - name: Check flake (package, unit tests, module assertions)
        run: nix flake check --no-write-lock-file -L
      - name: Run the two-node ZFS VM test
        run: nix build .#checks.x86_64-linux.integration --no-link --no-write-lock-file -L
```

`nix flake check` already builds `checks.x86_64-linux.integration` on the runner's system; the explicit step keeps its log readable. Keep both.

- [ ] **Step 2: Write `.github/workflows/release.yml`**

```yaml
name: Release

on:
  release:
    types: [published]

jobs:
  pypi:
    runs-on: ubuntu-latest
    environment:
      name: pypi
      url: https://pypi.org/p/zfs-tenant
    permissions:
      id-token: write
    steps:
      - uses: actions/checkout@v6
        with:
          fetch-depth: 0
      - name: Install uv
        uses: astral-sh/setup-uv@v7
      - name: Build
        run: uv build
      - name: Publish package distributions to PyPI
        uses: pypa/gh-action-pypi-publish@release/v1

  pyz:
    runs-on: ubuntu-latest
    permissions:
      contents: write
    steps:
      - uses: actions/checkout@v6
        with:
          fetch-depth: 0
      - name: Install uv
        uses: astral-sh/setup-uv@v7
      - name: Install just
        uses: extractions/setup-just@v3
      - name: Build the zipapp
        run: just pyz
      - name: Attach it to the release
        env:
          GH_TOKEN: ${{ github.token }}
        run: gh release upload "${{ github.event.release.tag_name }}" dist/zfs-tenant.pyz --clobber
```

- [ ] **Step 3: Copy the remaining workflow files from pytest-shm verbatim**

`.github/workflows/release-drafter.yml`, `.github/workflows/toc.yaml`, `.github/release-drafter.yml`, `.github/renovate.json` (contents as in `basnijholt/pytest-shm`).

- [ ] **Step 4: Final local verification**

Run: `just lint && just test && just pyz && nix flake check -L`
Expected: all pass.

- [ ] **Step 5: Commit, create the repository, and push**

```bash
git add -A
git commit -m "Add CI, release, and maintenance workflows"
gh repo create basnijholt/zfs-tenant --public --source . --remote origin \
  --description "Give a friend a quota-capped corner of your ZFS pool for raw encrypted backups, without giving them a shell" \
  --homepage "https://github.com/basnijholt/zfs-tenant"
git push -u origin main
gh repo edit basnijholt/zfs-tenant --add-topic zfs,openzfs,backup,syncoid,sanoid,nixos,ssh
```

- [ ] **Step 6: Watch CI**

Run: `gh run watch --exit-status` for the CI run on `main`.
Expected: all jobs green. Fix and push follow-up commits for any failure.
