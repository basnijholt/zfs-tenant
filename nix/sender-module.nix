# Sender side: push sanoid snapshots to friends with syncoid, as a user that can only `zfs send`
# (plus `hold`, because `zfs send -I` holds the snapshots it streams for the duration of the send).
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
      # The syncoid user is not root and may only send and hold; syncoid 2.3.0 pastes the
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
        description = "Mirror your snapshot retention on the host: delete target snapshots you no longer have.";
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
        description = "Delegate zfs send and hold to the zfs-tenant-sender user";
        wantedBy = [ "multi-user.target" ];
        wants = [ "zfs.target" ];
        after = [ "zfs.target" ];
        path = [ cfg.zfsPackage ];
        # Delegation is pool state, so reapply it on every boot and rebuild.
        script = lib.concatMapStringsSep "\n" (
          source: "zfs allow -u zfs-tenant-sender send,hold ${lib.escapeShellArg source}"
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
