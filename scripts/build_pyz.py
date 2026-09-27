"""Build the portable zipapp from one freshly built wheel."""  # noqa: INP001

import subprocess
import zipapp
from pathlib import Path
from shutil import copyfile
from tempfile import TemporaryDirectory
from zipfile import ZipFile


def main() -> None:
    """Keep the wheel's package, generated version, and entry point together."""
    build = Path("build")
    build.mkdir(exist_ok=True)
    Path("dist").mkdir(exist_ok=True)
    with TemporaryDirectory(dir=build) as temporary:
        work = Path(temporary)
        subprocess.run(["uv", "build", "--wheel", "--out-dir", str(work)], check=True)  # noqa: S603, S607
        [wheel] = work.glob("*.whl")
        staging = work / "pyz"
        with ZipFile(wheel) as archive:
            for member in archive.infolist():
                if member.filename.startswith("zfs_tenant/") and not member.is_dir():
                    target = staging / member.filename
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(archive.read(member))
        copyfile(staging / "zfs_tenant/__main__.py", staging / "__main__.py")
        zipapp.create_archive(
            staging,
            "dist/zfs-tenant.pyz",
            interpreter="/usr/bin/env python3",
            compressed=True,
        )
        # Retain the exact wheel for artifact checks; never select an older build here.
        wheels = build / "wheel"
        wheels.mkdir(exist_ok=True)
        copyfile(wheel, wheels / wheel.name)


if __name__ == "__main__":
    main()
