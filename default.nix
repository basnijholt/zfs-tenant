# Build without flakes: nix-build
{
  pkgs ? import <nixpkgs> { },
}:
pkgs.callPackage ./nix/package.nix { }
