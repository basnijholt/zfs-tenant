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
            services.zfs-tenant.package =
              lib.mkDefault
                self.packages.${pkgs.stdenv.hostPlatform.system}.default;
          };
      };

      checks = forAllSystems (
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
        in
        {
          package = self.packages.${system}.default;
          modules = import ./nix/module-test.nix {
            inherit lib pkgs system;
            hostModule = self.nixosModules.host;
          };
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
