# Adds pkgs.zfs-tenant: nixpkgs.overlays = [ (import ./nix/overlay.nix) ];
final: _prev: {
  zfs-tenant = final.callPackage ./package.nix { };
}
