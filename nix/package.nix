# The zfs-tenant package in callPackage form, so it builds without flakes:
#   pkgs.callPackage ./nix/package.nix { }
# Without git metadata the version defaults to pyproject's fallback; the flake passes one
# derived from the commit date, and `.override { version = "..."; }` sets any other.
{
  lib,
  python3Packages,
  version ? "0.0.0",
}:

python3Packages.buildPythonApplication {
  pname = "zfs-tenant";
  inherit version;
  pyproject = true;
  # Only tracked build and test inputs, so a local checkout's .venv, __pycache__, or
  # generated _version.py never enters the store.
  src = lib.fileset.toSource {
    root = ../.;
    fileset = lib.fileset.unions [
      ../pyproject.toml
      ../README.md
      ../LICENSE
      (lib.fileset.fileFilter (
        file: (file.hasExt "py" && file.name != "_version.py") || file.name == "py.typed"
      ) ../src)
      (lib.fileset.fileFilter (file: file.hasExt "py") ../tests)
    ];
  };
  build-system = with python3Packages; [
    hatchling
    hatch-vcs
  ];
  env.SETUPTOOLS_SCM_PRETEND_VERSION = version;
  nativeCheckInputs = [ python3Packages.pytestCheckHook ];
  pythonImportsCheck = [ "zfs_tenant" ];
  meta = {
    description = "Give a friend a quota-capped corner of your ZFS pool for raw encrypted backups";
    homepage = "https://github.com/basnijholt/zfs-tenant";
    license = lib.licenses.mit;
    mainProgram = "zfs-tenant";
    platforms = lib.platforms.linux;
  };
}
