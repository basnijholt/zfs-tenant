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
      };

      checks = forAllSystems (
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
          good = evalModules system exampleTenant;
          noPam = evalModules system (
            lib.recursiveUpdate exampleTenant { services.openssh.settings.UsePAM = false; }
          );
          noPamSession = evalModules system (
            lib.recursiveUpdate exampleTenant { security.pam.services.sshd.startSession = lib.mkForce false; }
          );
          duplicateUser = evalModules system (
            lib.recursiveUpdate exampleTenant {
              services.zfs-tenant.tenants.other = {
                dataset = "tank/friends/other";
                user = "zfs-tenant-joe";
                quota = "1T";
                authorizedKeys = [ "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestOnlyKey other" ];
                allowedFrom = [ "100.64.0.13" ];
              };
            }
          );
          customLimits = evalModules system (
            lib.recursiveUpdate exampleTenant {
              services.zfs-tenant.tenants.joe.resourceLimits = {
                memoryMax = "768M";
                tasksMax = 32;
                cpuQuota = "50%";
                processLimit = 96;
              };
            }
          );
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
            assert failedAssertions noPam != [ ];
            assert failedAssertions noPamSession != [ ];
            assert failedAssertions duplicateUser != [ ];
            assert lib.hasPrefix ''restrict,from="100.64.0.12",command="'' keyLine;
            assert lib.hasInfix " gate --root tank/friends/joe --zfs " keyLine;
            assert good.config.systemd.services ? zfs-tenant-setup-joe;
            assert good.config.systemd.services ? zfs-tenant-zone-joe;
            assert lib.hasInfix " --zone-pid-file /run/zfs-tenant/joe/holder.pid" keyLine;
            assert lib.hasInfix "--slice=zfs-tenant-joe.slice" keyLine;
            assert good.config.systemd.user.slices.zfs-tenant-joe.sliceConfig.MemoryMax == "512M";
            assert good.config.systemd.user.slices.zfs-tenant-joe.sliceConfig.TasksMax == 64;
            assert good.config.systemd.user.slices.zfs-tenant-joe.sliceConfig.CPUQuota == "100%";
            assert lib.any (limit: limit.domain == "zfs-tenant-joe" && limit.item == "nproc" && limit.value == "128") good.config.security.pam.loginLimits;
            assert customLimits.config.systemd.user.slices.zfs-tenant-joe.sliceConfig.MemoryMax == "768M";
            assert customLimits.config.systemd.user.slices.zfs-tenant-joe.sliceConfig.TasksMax == 32;
            assert customLimits.config.systemd.user.slices.zfs-tenant-joe.sliceConfig.CPUQuota == "50%";
            assert lib.any (limit: limit.domain == "zfs-tenant-joe" && limit.item == "nproc" && limit.value == "96") customLimits.config.security.pam.loginLimits;
            pkgs.runCommand "zfs-tenant-module-check" { } "touch $out";
        }
        # End-to-end VM test against real OpenZFS and syncoid; KVM only on x86_64-linux in CI.
        // lib.optionalAttrs (system == "x86_64-linux") {
          integration = import ./nix/integration-test.nix {
            inherit pkgs;
            hostModule = self.nixosModules.host;
          };
        }
      );
    };
}
