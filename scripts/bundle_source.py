from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE_DIRS = ("netvision", "scripts", "tests")
ALLOWED_SUFFIXES = {".py", ".qss", ".json"}
IGNORED_DIRS = {
    ".venv",
    "__pycache__",
    ".git",
    ".codex-backups",
    "build",
    "dist",
}
SEPARATOR = "\n\n========================================\n"


def iter_source_files() -> list[Path]:
    files = []
    for directory in SOURCE_DIRS:
        source_dir = ROOT / directory
        if not source_dir.is_dir():
            continue
        for path in source_dir.rglob("*"):
            if path.is_file() and path.suffix.lower() in ALLOWED_SUFFIXES:
                if not IGNORED_DIRS.intersection(path.relative_to(ROOT).parts):
                    files.append(path)
    return sorted(files)


def build_bundle() -> str:
    parts = []
    for path in iter_source_files():
        try:
            content = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        relative_path = path.relative_to(ROOT).as_posix()
        parts.append(
            f"{SEPARATOR}=== File: {relative_path} ===\n"
            f"========================================\n\n{content}"
        )
    return "".join(parts)


def main() -> None:
    output_path = ROOT / "netvision_source_bundle.txt"
    output_path.write_text(build_bundle(), encoding="utf-8")
    print(f"Bundled {len(iter_source_files())} source files into {output_path}")


if __name__ == "__main__":
    main()
