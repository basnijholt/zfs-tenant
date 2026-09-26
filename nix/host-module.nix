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

  zonePidFile = name: "/run/zfs-tenant/${name}/holder.pid";

  gateCommand =
    name: tenant:
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
        "--zone-pid-file"
        (zonePidFile name)
      ]
      ++ lib.optional (!tenant.requireEncryption) "--no-require-encryption"
    );

  forcedCommandKey =
    name: tenant: key:
    ''restrict,from="${lib.concatStringsSep "," tenant.allowedFrom}",command="${gateCommand name tenant}" ${key}'';

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
      name: tenant:
      lib.nameValuePair tenant.user {
        isSystemUser = true;
        group = "zfs-tenant";
        home = "/var/empty";
        # sshd runs the forced command through the login shell.
        shell = pkgs.runtimeShell;
        openssh.authorizedKeys.keys = map (forcedCommandKey name tenant) tenant.authorizedKeys;
      }
    ) cfg.tenants;

    systemd.services = lib.concatMapAttrs (name: tenant: {
      "zfs-tenant-setup-${name}" = {
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
      };

      # The tenant's user namespace. `zfs zone` attaches the root to it, so every zfs
      # command the gate runs in there only sees the tenant's own datasets.
      "zfs-tenant-zone-${name}" = {
        description = "User namespace that hides the rest of the pool from tenant ${name}";
        wantedBy = [ "multi-user.target" ];
        requires = [ "zfs-tenant-setup-${name}.service" ];
        after = [ "zfs-tenant-setup-${name}.service" ];
        serviceConfig = {
          ExecStart = lib.escapeShellArgs [
            tenantBin
            "zone"
            "--root"
            tenant.dataset
            "--user"
            tenant.user
            "--pid-file"
            (zonePidFile name)
            "--zfs"
            zfsBin
          ];
          RuntimeDirectory = "zfs-tenant/${name}";
          Restart = "always";
          RestartSec = 5;
        };
      };
    }) cfg.tenants;
  };
}
