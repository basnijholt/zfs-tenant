# Evaluate the public module contract without booting a VM.
{
  lib,
  pkgs,
  system,
  hostModule,
}:
let
  eval =
    extra:
    lib.nixosSystem {
      inherit system;
      modules = [
        hostModule
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
  tenant = {
    dataset = "tank/friends/joe";
    quota = "2T";
    authorizedKeys = [ "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestOnlyKey joe" ];
    allowedFrom = [ "100.64.0.12" ];
  };
  baseline = {
    services.zfs-tenant = {
      enable = true;
      tenants.joe = tenant;
    };
  };
  changed = extra: eval (lib.recursiveUpdate baseline extra);
  changedTenant = extra: changed { services.zfs-tenant.tenants.joe = extra; };
  good = eval baseline;
  failsWith =
    evaluated: expected: lib.any (a: !a.assertion && a.message == expected) evaluated.config.assertions;
  succeeds =
    evaluated:
    let
      failures = builtins.filter (a: !a.assertion) evaluated.config.assertions;
    in
    failures == [ ] || throw (lib.concatMapStringsSep "\n" (a: a.message) failures);
  rootsMessage = "services.zfs-tenant.tenants datasets must be distinct and must not contain each other.";
  datasetMessage = "services.zfs-tenant.tenants.joe.dataset must be a safe dataset below a pool.";
  fromMessage = "services.zfs-tenant.tenants.joe.allowedFrom must list patterns without quotes, commas, or newlines.";
  keyMessage = "services.zfs-tenant.tenants.joe.authorizedKeys must list at least one single-line key.";
  resourceMessage = "services.zfs-tenant.tenants.joe.resourceLimits memoryMax and cpuQuota must be nonempty systemd values.";
  # Each case must fail for its intended reason, even if NixOS adds other assertions.
  rejected = {
    disabledSsh = failsWith (changed {
      services.openssh.enable = lib.mkForce false;
    }) "services.zfs-tenant requires services.openssh.enable = true.";
    disabledPam = failsWith (changed {
      services.openssh.settings.UsePAM = false;
    }) "services.zfs-tenant requires services.openssh.settings.UsePAM = true for user scopes.";
    disabledPamSession = failsWith (changed {
      security.pam.services.sshd.startSession = lib.mkForce false;
    }) "services.zfs-tenant requires security.pam.services.sshd.startSession = true for user scopes.";
    duplicateUsers = failsWith (changed {
      services.zfs-tenant.tenants.other = tenant // {
        dataset = "tank/friends/other";
        user = "zfs-tenant-joe";
      };
    }) "services.zfs-tenant requires a distinct user for each tenant.";
    duplicateRoots = failsWith (changed { services.zfs-tenant.tenants.other = tenant; }) rootsMessage;
    nestedRoots = failsWith (changed {
      services.zfs-tenant.tenants.other = tenant // {
        dataset = "tank/friends/joe/other";
      };
    }) rootsMessage;
    invalidTenant = failsWith (changed {
      services.zfs-tenant.tenants.Bad = tenant // {
        dataset = "tank/friends/other";
        user = "backup-other";
      };
    }) "services.zfs-tenant.tenants.Bad: names must match [a-z][a-z0-9-]{0,20}.";
    invalidUser = failsWith (changedTenant {
      user = "bad user";
    }) "services.zfs-tenant.tenants.joe.user must be a simple local user name.";
    poolOnly = failsWith (changedTenant { dataset = "tank"; }) datasetMessage;
    emptyDataset = failsWith (changedTenant { dataset = ""; }) datasetMessage;
    emptyComponent = failsWith (changedTenant { dataset = "tank//joe"; }) datasetMessage;
    dotComponent = failsWith (changedTenant { dataset = "tank/./joe"; }) datasetMessage;
    parentComponent = failsWith (changedTenant { dataset = "tank/../joe"; }) datasetMessage;
    dashComponent = failsWith (changedTenant { dataset = "tank/-joe"; }) datasetMessage;
    emptyKeys = failsWith (changedTenant { authorizedKeys = [ ]; }) keyMessage;
    emptyFrom = failsWith (changedTenant { allowedFrom = [ ]; }) fromMessage;
    quotedFrom = failsWith (changedTenant { allowedFrom = [ "host\"name" ]; }) fromMessage;
    commaFrom = failsWith (changedTenant { allowedFrom = [ "host,other" ]; }) fromMessage;
    newlineFrom = failsWith (changedTenant { allowedFrom = [ "host\nother" ]; }) fromMessage;
    carriageReturnFrom = failsWith (changedTenant { allowedFrom = [ "host\rother" ]; }) fromMessage;
    emptyMemory = failsWith (changedTenant { resourceLimits.memoryMax = ""; }) resourceMessage;
    emptyCpu = failsWith (changedTenant { resourceLimits.cpuQuota = ""; }) resourceMessage;
  };
  twoTenants = changed {
    services.zfs-tenant.tenants = {
      joe = {
        user = "backup-joe";
        resourceLimits = {
          memoryMax = "768M";
          tasksMax = 32;
          cpuQuota = "50%";
          processLimit = 96;
        };
      };
      ann = {
        user = "backup-ann";
        dataset = "tank/friends/ann";
        quota = "1T";
        authorizedKeys = [ "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestOnlyAnnKey ann" ];
        allowedFrom = [ "100.64.0.13" ];
        resourceLimits = {
          memoryMax = "256M";
          tasksMax = 16;
          cpuQuota = "25%";
          processLimit = 48;
        };
      };
    };
  };
  # Malformed keys fail the option type before module assertions can inspect them.
  keysEvaluate =
    evaluated:
    (builtins.tryEval (
      builtins.deepSeq evaluated.config.services.zfs-tenant.tenants.joe.authorizedKeys true
    )).success;
  # Check each account's emitted commands, units and both PAM limits independently.
  tenantMatches =
    evaluated: name:
    {
      user,
      root,
      quota,
      from,
      memory,
      tasks,
      cpu,
      processes,
    }:
    let
      cfg = evaluated.config;
      keys = cfg.users.users.${user}.openssh.authorizedKeys.keys;
      key = builtins.head keys;
      setup = cfg.systemd.services."zfs-tenant-setup-${name}";
      zone = cfg.systemd.services."zfs-tenant-zone-${name}";
      slice = cfg.systemd.user.slices."zfs-tenant-${name}".sliceConfig;
    in
    builtins.length keys == 1
    && lib.hasPrefix ''restrict,from="${from}",command="'' key
    && lib.hasInfix " gate --root ${root} --zfs " key
    && lib.hasInfix " --zone-pid-file /run/zfs-tenant/${name}/holder.pid" key
    && lib.hasInfix "--slice=zfs-tenant-${name}.slice" key
    && lib.hasInfix (lib.escapeShellArgs [
      "setup"
      "--root"
      root
      "--user"
      user
      "--quota"
      quota
    ]) setup.serviceConfig.ExecStart
    && lib.hasInfix (lib.escapeShellArgs [
      "zone"
      "--root"
      root
      "--user"
      user
      "--pid-file"
      "/run/zfs-tenant/${name}/holder.pid"
    ]) zone.serviceConfig.ExecStart
    && zone.requires == [ "zfs-tenant-setup-${name}.service" ]
    && zone.after == [ "zfs-tenant-setup-${name}.service" ]
    && zone.serviceConfig.RuntimeDirectory == "zfs-tenant/${name}"
    && slice.MemoryMax == memory
    && slice.TasksMax == tasks
    && slice.CPUQuota == cpu
    &&
      lib.all
        (
          type:
          lib.any (
            limit:
            limit.domain == user && limit.type == type && limit.item == "nproc" && limit.value == processes
          ) cfg.security.pam.loginLimits
        )
        [
          "soft"
          "hard"
        ];
in
assert succeeds good;
assert keysEvaluate good;
assert
  !(keysEvaluate (changedTenant {
    authorizedKeys = [ "ssh-ed25519 test\rcomment" ];
  }));
assert
  !(keysEvaluate (changedTenant {
    authorizedKeys = [ "ssh-ed25519 test\ncomment" ];
  }));
assert lib.all (name: rejected.${name} || throw "module rejection case failed: ${name}") (
  builtins.attrNames rejected
);
assert tenantMatches good "joe" {
  user = "zfs-tenant-joe";
  root = "tank/friends/joe";
  quota = "2T";
  from = "100.64.0.12";
  memory = "512M";
  tasks = 64;
  cpu = "100%";
  processes = "128";
};
assert succeeds twoTenants;
assert tenantMatches twoTenants "joe" {
  user = "backup-joe";
  root = "tank/friends/joe";
  quota = "2T";
  from = "100.64.0.12";
  memory = "768M";
  tasks = 32;
  cpu = "50%";
  processes = "96";
};
assert tenantMatches twoTenants "ann" {
  user = "backup-ann";
  root = "tank/friends/ann";
  quota = "1T";
  from = "100.64.0.13";
  memory = "256M";
  tasks = 16;
  cpu = "25%";
  processes = "48";
};
pkgs.runCommand "zfs-tenant-module-check" { } "touch $out"
