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
    in
    {
      packages = forAllSystems (system: {
        default = nixpkgs.legacyPackages.${system}.callPackage ./nix/package.nix { inherit version; };
      });

      overlays.default = import ./nix/overlay.nix;

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
          # The bare module, as imported without flakes; the VM test covers the flake module.
          modules = import ./nix/module-test.nix {
            inherit lib pkgs system;
            hostModule = ./nix/host-module.nix;
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
