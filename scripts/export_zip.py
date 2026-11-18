from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

ROOT = Path(__file__).resolve().parents[1]
ARCHIVE_NAME = "NetVision-main.zip"
ARCHIVE_ROOT = "NetVision-main"
DIRECTORIES = ("fonts", "netvision", "scripts", "tests")
FILES = (
    ".gitignore",
    "EULA.txt",
    "LICENSE",
    "NetVision.ico",
    "NOTICE.txt",
    "pyproject.toml",
    "README.md",
    "requirements.txt",
)


def _is_excluded(path: Path) -> bool:
    relative_parts = path.relative_to(ROOT).parts
    return "__pycache__" in relative_parts or path.suffix.lower() == ".pyc"


def _iter_files() -> list[Path]:
    paths = [ROOT / name for name in FILES]
    for directory in DIRECTORIES:
        source = ROOT / directory
        if not source.is_dir():
            continue
        paths.extend(path for path in source.rglob("*") if path.is_file())
    return sorted(path for path in paths if path.is_file() and not _is_excluded(path))


def create_archive() -> Path:
    archive_path = ROOT / ARCHIVE_NAME
    with ZipFile(archive_path, "w", compression=ZIP_DEFLATED) as archive:
        for path in _iter_files():
            relative = path.relative_to(ROOT).as_posix()
            archive.write(path, f"{ARCHIVE_ROOT}/{relative}")
    return archive_path


def main() -> None:
    archive_path = create_archive()
    print(f"Archive created successfully: {archive_path}")
    print(f"Size: {archive_path.stat().st_size:,} bytes")


if __name__ == "__main__":
    main()
