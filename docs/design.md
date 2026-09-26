---
icon: lucide/target
---

# Design goals

Two friends back each other up with plain `zfs send` and `zfs receive`, over SSH on a shared tailnet, with sanoid for snapshots and syncoid for transport.
Each host gives the other one dataset, the *tenant root* (for example `tank/friends/joe`), with a size cap.

## Goals

1. The tenant cannot see any of the host's data, including metadata such as dataset names, sizes, and properties.
2. The tenant cannot change or destroy anything of the host's.
3. The host cannot read the tenant's data: the keys never leave the tenant's machines.
4. Inside its root, the tenant can create and remove nested datasets.
5. Total usage is capped.
6. sanoid and syncoid keep working, with no VM, no iSCSI, and no ZFS-on-ZFS.
7. It is simpler than the [TrueNAS VM on an iSCSI zvol](https://www.nijho.lt/post/truenas-remote-backups/) it replaces.

The [security model](security.md) shows which mechanism enforces each goal and what still leaks.

## Constraints

- One host runs TrueNAS SCALE, so the host side must work without NixOS.
  The gate uses only the Python standard library and ships as a single `zfs-tenant.pyz` file.
- Every other machine runs NixOS, so a NixOS module is the main setup path on the host.
  The sending side needs nothing from this project: nixpkgs' `services.syncoid` pushes as an unprivileged user.
- The host runs OpenZFS 2.2 or newer, for `zfs zone`.

## Non-goals

- **Hiding the tenant's metadata from the host.**
  OpenZFS encryption leaves dataset and snapshot names, the hierarchy, properties, and sizes in plaintext.
- **Protecting backup availability from the host.**
  Root on the host can always destroy the copy; it can never read it.
- **Protecting a tenant's backups from its own compromised machine.**
  A leaked tenant key can delete that tenant's backups.
- **Pull replication or zrepl.**
  Restores use a plain `zfs send` through the gate.
- **Containers or VMs.**
  Only ZFS needs isolating, and `zfs zone` isolates exactly that.

## Principles

- **The kernel is the jail.**
  `zfs allow`, `quota`, the dataset and snapshot limits, and `zfs zone` enforce the boundary.
  The gate only removes the shell and scopes names, and stays small enough to audit in one sitting.
- **The gate never uses a shell.**
  It tokenizes the command, checks every name against the tenant root, and runs `zfs` with an argument list it builds itself.
- **New gate commands only for real clients.**
  A form is allowed only when syncoid or a restore needs it.
