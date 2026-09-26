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
            assert good.config.systemd.services ? zfs-tenant-zone-joe;
            assert lib.hasInfix " --zone-pid-file /run/zfs-tenant/joe/holder.pid" keyLine;
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
