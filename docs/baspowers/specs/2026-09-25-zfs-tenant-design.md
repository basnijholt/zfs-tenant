# zfs-tenant design

Date: 2026-09-25 (revised the same day: grace holds removed, `zfs zone` added)

## Goal

Two friends back each other up with plain `zfs send`/`zfs receive`, over SSH on a shared tailnet, using sanoid for snapshots and syncoid for transport.
Each host gives the other one dataset (the *tenant root*, e.g. `tank/friends/joe`) with a size cap.

Requirements, in the friends' words:

1. The tenant cannot see any of the host's data, including metadata (dataset names, sizes, properties).
2. The tenant cannot change or destroy anything of the host's.
3. The host cannot read the tenant's data: keys never leave the tenant's machines.
4. Inside the tenant root, the tenant may create and remove nested datasets.
5. Total usage is capped.
6. Sanoid/syncoid keep working, with no VM, no iSCSI, no ZFS-on-ZFS.
7. It must be simpler than the previous TrueNAS VM + iSCSI setup.

Additional constraints discovered during design:

- Joe's NAS still runs TrueNAS SCALE, so the host side must work without NixOS: the gate uses the Python standard library only and ships as a single-file `zfs-tenant.pyz` release asset alongside the PyPI package.
- Everything else in both fleets is NixOS, so a NixOS module is the primary setup path.

## Non-goals

- Hiding the tenant's metadata from the host. OpenZFS encryption leaves dataset and snapshot names, hierarchy, properties, and sizes in plaintext (`zfs-load-key(8)`). The README documents this and recommends neutral dataset names.
- Protecting backup *availability* from the host. Root on the host can always destroy the copy; it can never read it.
- Pull-based replication, zrepl support, or syncoid-pull restores. Restores use a plain `zfs send` through the gate.
- Protecting a tenant's backups from the tenant's own compromised machine (grace-period holds). Not an owner requirement; removed after the first implementation.
- Containers or VMs. Only ZFS needs isolating, and `zfs zone` isolates exactly that; a container would still need `/dev/zfs`.

## Security model

The kernel is the jail; the gate removes the shell.

| Promise | Enforced by |
|---|---|
| Tenant cannot touch host datasets | `zfs allow` delegation exists only on the tenant root, verified in a VM: receive, destroy, send, set, and allow outside the subtree return `permission denied` |
| Tenant cannot delete or reconfigure the tenant root | root gets `-l` (local) `create,mount,receive` only; descendants get `-d` rights; verified: `destroy`, `snapshot`, `set quota`, `set filesystem_limit`, `allow` on the root are denied |
| Size cap | `quota` on the root, set by root, not delegated; verified: receive past it fails with `space quota exceeded` |
| No dataset/snapshot flooding | `filesystem_limit`, `snapshot_limit` on the root; OpenZFS enforces them only for users who cannot change them, i.e. exactly delegated tenants; verified |
| Tenant cannot see host metadata | forced command; the gate scopes every `list`/`get` to the tenant root, allowlists properties, rejects out-of-scope names before calling `zfs`, and answers `ps`/`command -v` probes with nothing; verified that *without* a gate any local user can `zfs list` and `zfs get` host datasets |
| Host cannot read tenant data | raw sends (`zfs send -w`); `requireEncryption` (default on) makes the gate destroy any received dataset with `encryption=off`; verified `keystatus=unavailable` on the host |
| No hostile mounts | root properties `zoned=on` (never mounted, so never shared, on the host), `mountpoint=none`, `canmount=off`, `readonly=on`, `exec=off`, `setuid=off`, `devices=off`, `volmode=none`; the gate always receives with `-u`; verified: a stream carrying `mountpoint=/etc/evil` yields `cannot receive mountpoint property ... permission denied` and the dataset stays at `mountpoint=none`; a root `zfs mount -a` mounts nothing of the tenant's; received zvols get no `/dev/zvol` node |
| Tenant cannot see host metadata even if the gate has a bug | every gate process runs inside the tenant's user namespace, to which `zfs zone` attached the root; the kernel returns `dataset does not exist` for everything else; verified in a VM |
| No arbitrary commands | forced command with `restrict`; the gate exec's `zfs` with an argv it builds itself, never a shell |

Residual risks, documented in the README:

- The kernel parses tenant-supplied send streams.
- The host always sees tenant metadata (non-goal above).
- A leaked tenant key can push data up to the quota and delete non-held snapshots.
- syncoid 2.3.0 pastes the receiver's resume token unescaped into a shell on the sender (`open FH, "$getsendsizecmd 2>&1 |"` with `$snaps = "-t $receivetoken"`), so a malicious host can run commands on the sender as the syncoid user. The sender module therefore runs syncoid as a non-root user that holds only `zfs send` and `hold` rights.

## Architecture

```
src/zfs_tenant/
├── __init__.py    # version
├── __main__.py    # python -m zfs_tenant
├── cli.py         # argparse: gate, setup, zone, authorized-key
├── names.py       # dataset/snapshot name validation and scoping
├── grammar.py     # SSH_ORIGINAL_COMMAND -> Request (pure, no I/O)
├── gate.py        # Request -> zfs argv, execution, post-receive checks, syslog
├── setup.py       # idempotent tenant-root creation, properties, delegation
├── zone.py        # holder + zfs zone (root side), setns (gate side)
└── zfs.py         # thin subprocess runner with an injectable zfs path
nix/
├── host-module.nix     # services.zfs-tenant (tenants, setup and zone units)
├── sender-module.nix   # services.zfs-tenant-sender (syncoid push timers)
└── integration-test.nix
```

Python >= 3.10, standard library only.
Distribution `zfs-tenant`, import package `zfs_tenant`, console script `zfs-tenant`.

### names.py

- A dataset component matches `[A-Za-z0-9_.:-]+`, is not `.` or `..`, and does not start with `-`.
- A snapshot name matches `[A-Za-z0-9_.:-]+` (no `%`, so no `zfs destroy` ranges, and no `@`, `#`, `/`).
- `in_scope(root, name)` is true iff `name == root` or `name.startswith(root + "/")`; `tank/friends/joe2` is not inside `tank/friends/joe`.
- `strictly_below(root, name)` excludes the root itself; destroy and receive targets must be strictly below.

### grammar.py

Input: the raw `SSH_ORIGINAL_COMMAND` string plus the tenant root.
Output: one of four frozen dataclasses (`Reply`, `Run`, `Receive`, `ResumeSend`), or `Rejected(reason)`.

Tokenizing: `shlex.shlex(command, posix=True, punctuation_chars=";|&<>")` with `whitespace_split=True`.
Any token that is punctuation other than `;` alone or the exact redirect sequence `2 >& 1` at the end of a receive is rejected.
Quotes are resolved by shlex; the resulting tokens are then validated by `names.py`, so quoting tricks cannot smuggle characters past validation.
The gate never hands a token to a shell, so tokenizer differences from `sh` cannot cause execution; they can only cause rejection.

Accepted requests (D = dataset in scope, D↓ = strictly below root, S = snapshot name):

| Tokens | Request | Executes |
|---|---|---|
| `exit` | `Reply` | nothing, exit 0 |
| `echo -n` | `Reply` | nothing, exit 0 |
| `command -v NAME` | `Reply` | nothing, exit 1 (so syncoid uses no mbuffer and no compression on the target) |
| `ps -Ao args=` | `Reply` | nothing, exit 0 (a real `ps` would leak the host process list) |
| `zpool get -o value -H feature@extensible_dataset POOL` | `Run` | same, only when POOL is the root's pool |
| `zfs get -H name D` | `Run` | same |
| `zfs get -H receive_resume_token D` | `Run` | same |
| `zfs get -H -p used D` | `Run` | same |
| `zfs get -Hpd 1 -t snapshot guid,creation D` | `Run` | same |
| `zfs get -Hpd 1 type,guid,creation D` | `Run` | same |
| `zfs receive [-s] [-F] [-u] D↓ [2 >& 1]` | `Receive` | `zfs receive -u [-s] D↓`, stderr merged into stdout; `-F` is dropped |
| `zfs receive -A D↓` | `Run` | same |
| `zfs destroy [-r] D↓@S[,S]...` | `Run` | same |
| `zfs destroy D↓@S ; zfs destroy D↓@S ...` (same D) | `Run` | one `zfs destroy D↓@S,S` |
| `zfs destroy [-r] D↓` | `Run` | same |
| `zfs create [-p] D↓` | `Run` | same |
| `zfs list [FLAGS] [D]` | `Run` | `zfs list FLAGS D`, D defaults to root |
| `zfs send [-wLceRp...] [-i\|-I @S] D@S` | `Run` | same, for restores |
| `zfs send [-wLceRp...] [-i\|-I D@S] D@S` | `Run` | same |
| `zfs send -t TOKEN` | `ResumeSend` | same, after `zfs send -nvPt TOKEN` shows a `toname` in scope |

`zfs list` flags: `-H`, `-p`, `-r`, `-d N`, `-t T[,T]` with T in `filesystem,volume,snapshot,bookmark,all`, `-o C[,C]` with C from an allowlist (`name,used,available,avail,referenced,refer,logicalused,creation,type,encryption,keystatus,encryptionroot,userrefs,defer_destroy,quota,filesystem_count,snapshot_count,filesystem_limit,snapshot_limit,receive_resume_token,guid`), `-s C` / `-S C` with C from the same allowlist.
Syncoid's `sudo` form is rejected: senders must pass `--no-privilege-elevation`.
Everything else is rejected with `zfs-tenant: command not allowed` on stderr, exit 126, without running anything.
`-i/-I` accepts both `@S` and `D@S`; a full `D@S` origin must be the same dataset.

### gate.py

- Reads `SSH_ORIGINAL_COMMAND` from the environment (never argv), parses it, logs `tenant=<name> allowed|denied cmd=<repr>` to syslog (`LOG_AUTH`), executes.
- Executes `zfs`/`zpool` by absolute path (from CLI flags) with `subprocess.run`, inheriting stdin/stdout so streams pass straight through; `Receive` redirects the child's stderr to stdout.
- `Receive` with `requireEncryption` (default):
  - Before receiving: if `D↓` exists with `encryption=off`, refuse without reading the stream.
    Otherwise record the set of datasets under `D↓`.
  - After receiving: any dataset under `D↓` that is new and has `encryption=off` is removed with `zfs destroy -r`, the gate prints `zfs-tenant: refused unencrypted dataset <name>; send raw (zfs send -w)` and exits 1.
    Pre-existing datasets are never destroyed by the gate.
- `ResumeSend` decodes the token with `zfs send -nvPt TOKEN` and requires the `toname` dataset in scope.
- Exit status is the child's exit status.

### setup.py

`zfs-tenant setup --root R --user U --quota Q [--reservation Q] [--filesystem-limit N] [--snapshot-limit N] [--dry-run]`, run as root.

1. `zfs create -p R` (a no-op when R exists).
2. `zfs set` on R: `quota`, optional `reservation`, `filesystem_limit`, `snapshot_limit`, `mountpoint=none`, `canmount=off`, `readonly=on`, `exec=off`, `setuid=off`, `devices=off`, `volmode=none`, `zoned=on` (OpenZFS refuses `sharenfs`/`sharesmb` on zoned datasets, and a zoned dataset is never mounted, so never shared, on the host).
3. `zfs unallow -u U R` (clears previous rights), then `zfs allow -l -u U create,mount,receive R` and `zfs allow -d -u U create,destroy,mount,receive,send R`.
4. `--dry-run` prints the commands instead of running them, which is also the documented manual path on TrueNAS.

Defaults: `filesystem_limit=100`, `snapshot_limit=20000`.
Setup refuses a root whose pool lacks `feature@filesystem_limits`.

### zone.py

Verified in a VM with OpenZFS 2.4.4:

| Inside the attached namespace | tenant mapped to root (`--map-root-user`) | tenant mapped to its own uid |
|---|---|---|
| `tank/host` hidden (`dataset does not exist`) | yes | yes |
| destroy the tenant root | allowed (namespace root is zone admin, bypasses `zfs allow`) | `permission denied` |
| set properties on children (`mountpoint`) | allowed | `permission denied` |
| change `quota`/`filesystem_limit` on the root | `permission denied` | `permission denied` |
| ancestors' `used`/`available`, `zpool list`/`status` | visible | visible (the gate blocks these commands) |

So the tenant keeps its own uid inside the namespace.

- `zfs-tenant zone --root R --user U --pid-file P --zfs PATH`, run as root in the foreground (a systemd service on NixOS, a post-init script on TrueNAS).
  - Forks a holder that clears its signal mask, drops to U (`setgroups([])`, `setgid`, `setuid`), sets itself dumpable again (so U's gate processes may open `/proc/<pid>/ns/user`), calls `unshare(CLONE_NEWUSER)`, writes `setgroups=deny` and the one-line uid and gid maps `U U 1`, signals readiness over a pipe, and sleeps.
  - The parent checks the holder is in a different user namespace, opens its namespace file (so it can detach even after the holder dies), runs `zfs zone /proc/<parent>/fd/<n> R`, writes P (0644, atomically), and waits for SIGTERM, SIGINT, or SIGCHLD.
  - On exit: removes P, kills and reaps the holder, runs `zfs unzone`. Exit 0 on a requested stop, 1 when the holder died.
  - OpenZFS takes a reference on the namespace when attaching, so a namespace id is never reused while attached.
- `enter(P)` (gate side): reads the pid, opens `/proc/<pid>/ns/user`, `setns(fd, CLONE_NEWUSER)` (`os.setns` on 3.12+, libc through ctypes before that), and verifies the process's user namespace changed. Any failure raises `ZoneError`; the gate prints `zfs-tenant: the tenant namespace is not running (...)` and exits 1 without running anything.
- OpenZFS master adds uid-based zoning (`zoned_uid`), which would remove the holder; not released in 2.4.

### cli.py

- `zfs-tenant gate --root R --zfs PATH --zpool PATH [--no-require-encryption]`
- `zfs-tenant setup ...` (above)
- `zfs-tenant zone ...` (above)
- `zfs-tenant gate ... --zone-pid-file P` joins the zone before parsing.
- `zfs-tenant authorized-key --gate-command CMD --from ADDR[,ADDR] KEY` prints a `restrict,from="...",command="..." KEY` line for manual setups.

### host-module.nix

```nix
services.zfs-tenant = {
  enable = true;
  tenants.joe = {
    dataset = "tank/friends/joe";
    quota = "2T";
    reservation = null;          # set to the quota to hide pool fill level and guarantee space
    filesystemLimit = 100;
    snapshotLimit = 20000;
    requireEncryption = true;
    authorizedKeys = [ "ssh-ed25519 AAAA... joe" ];
    allowedFrom = [ "100.64.0.12" ];
  };
};
```

Per tenant: a system user `zfs-tenant-<name>` with `pkgs.runtimeShell`, an `authorized_keys` line with `restrict,from=...,command=<gate>`, and a oneshot `zfs-tenant-setup-<name>.service` after `zfs.target` that runs `zfs-tenant setup` on every boot and rebuild (delegation is pool state).
A `zfs-tenant-zone-<name>.service` per tenant (requires the setup unit, `Restart=always`, `RuntimeDirectory=zfs-tenant/<name>`) runs `zfs-tenant zone` with the pid file `/run/zfs-tenant/<name>/holder.pid`, which the forced command passes to the gate.
Assertions mirror zfs-unlock: sshd enabled, non-empty keys and `allowedFrom`, safe dataset names, no quotes or newlines in `from=` patterns or keys.

### sender-module.nix

```nix
services.zfs-tenant-sender = {
  enable = true;
  targets.bas = {
    host = "bas-nas";                          # tailnet name or address
    user = "zfs-tenant-joe";
    sshKey = "/var/lib/zfs-tenant-sender/id_ed25519";
    knownHosts = "bas-nas ssh-ed25519 AAAA...";
    datasets."tank/offsite" = "tank/friends/joe/offsite";
    recursive = true;
    deleteTargetSnapshots = true;
    onCalendar = "daily";
  };
};
```

Runs syncoid as the system user `zfs-tenant-sender` with `zfs allow -u zfs-tenant-sender send,hold` on each source dataset (`zfs send -I` holds the snapshots it streams) (a oneshot reapplies it on boot), flags `--no-privilege-elevation --no-sync-snap --sendoptions=w --compress=none [--recursive] [--delete-target-snapshots]` plus `--sshkey`, `--sshoption=UserKnownHostsFile=<pinned>` and `--sshoption=StrictHostKeyChecking=yes`.
`--no-sync-snap` means only sanoid snapshots are sent and the sender user needs no `snapshot` or `destroy` rights; failures reach `OnFailure=` if the user wires one.

## Testing

- **Unit tests** (pytest, no ZFS): `names`, `grammar` (every accepted form plus adversarial input: `$(...)`, backticks, `&&`, newline, `'"'"'`, `%` ranges (rejected), `..`, sibling-prefix roots, the root itself, sudo form, extra flags, `-o`/`-x` receive options), `gate` with fake side effects, `setup` against a recording runner, the zone's failure paths without root, and the CLI.
- **VM integration test** (`nix build .#checks.x86_64-linux.integration`): two NixOS nodes with real OpenZFS, the host module, the sender module, real sshd, and real syncoid 2.3.0.
  Subtests: setup applied; full and incremental recursive push; host sees `keystatus=unavailable`; tenant `zfs list` shows only the subtree; escapes denied (host dataset get/destroy, root destroy, sibling receive, arbitrary command, sudo form); quota exceeded; plaintext stream refused and removed; interrupted receive resumes; `--delete-target-snapshots` mirrors the sender's retention; the tenant creates and removes datasets; the kernel hides `tank/host` inside the zone; the gate fails closed while the zone is down and recovers on restart; restore via `zfs send -w` through the gate and `zfs load-key` on the sender.
- **Module eval check**: host and sender modules evaluate and their assertions fire on bad input.

## Packaging and repository

Mirrors `basnijholt/pytest-shm`: src layout, hatchling + hatch-vcs, uv, ruff (`ALL`), mypy strict, ty, prek/pre-commit, justfile, `CLAUDE.md` with `AGENTS.md`/`GEMINI.md` symlinks, animated `docs/logo.svg`, README with TOC.
Workflows: CI (pytest 3.10-3.14, lint, Nix job with KVM running flake checks and the VM test), release (PyPI trusted publishing plus the `.pyz` asset built with `python -m zipapp`), release-drafter, TOC, renovate.
Public repository `github.com/basnijholt/zfs-tenant`.
