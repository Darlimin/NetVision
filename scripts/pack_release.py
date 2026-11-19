"""Package the newest completed Windows build for GitHub Releases."""

from pathlib import Path
from runpy import run_path
from tempfile import NamedTemporaryFile
from zipfile import ZIP_DEFLATED, ZipFile

ROOT = Path(__file__).resolve().parent.parent
RELEASE = ROOT / "release"
VERSION = run_path(str(ROOT / "netvision" / "version.py"))["__version__"]
ARCHIVE = RELEASE / f"NetVision-v{VERSION}-windows-amd64.zip"


def main() -> int:
    candidates = [
        folder / "dist" / "NetVision"
        for folder in RELEASE.glob("pyinstaller-*")
        if (folder / "dist" / "NetVision" / "NetVision.exe").is_file()
    ]
    if not candidates:
        raise SystemExit(f"No completed NetVision builds found in {RELEASE}")
    source = max(candidates, key=lambda path: (path.parents[1].stat().st_mtime_ns, path.parts))
    with NamedTemporaryFile(prefix=".netvision-", suffix=".zip", dir=RELEASE, delete=False) as tmp:
        temporary = Path(tmp.name)
    try:
        with ZipFile(temporary, "w", compression=ZIP_DEFLATED, compresslevel=6) as archive:
            for path in sorted(source.rglob("*")):
                if path.is_file():
                    archive.write(path, path.relative_to(source.parent))
        with ZipFile(temporary) as archive:
            if "NetVision/NetVision.exe" not in archive.namelist():
                raise RuntimeError("The archive does not contain NetVision.exe")
            corrupt = archive.testzip()
            if corrupt is not None:
                raise RuntimeError(f"Corrupt archive entry: {corrupt}")
        temporary.replace(ARCHIVE)
    finally:
        temporary.unlink(missing_ok=True)
    print(f"Build: {source}\nArchive: {ARCHIVE}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
