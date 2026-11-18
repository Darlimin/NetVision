"""Run the complete local NetVision quality and release check pipeline."""

from __future__ import annotations

from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


CHECKS = (
    ("Ruff", ("-m", "ruff", "check", "netvision", "scripts", "tests")),
    ("Changed-function complexity", ("scripts/check_complexity.py",)),
    (
        "Black",
        ("-m", "black", "--check", "--no-cache", "netvision", "scripts", "tests"),
    ),
    ("AST auditor", ("scripts/code_auditor.py", "netvision")),
    (
        "Vulture",
        ("-m", "vulture", "netvision", "vulture_whitelist.py", "--min-confidence", "80"),
    ),
    ("Pytest", ("-m", "pytest", "-q")),
    ("Release check", ("scripts/check_release.py",)),
)


def main() -> int:
    for name, arguments in CHECKS:
        print(f"\n=== {name} ===", flush=True)
        completed = subprocess.run(
            [sys.executable, *arguments],
            cwd=ROOT,
            check=False,
        )
        if completed.returncode:
            print(f"{name} failed with exit code {completed.returncode}", file=sys.stderr)
            return completed.returncode
    print("\nAll NetVision checks passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
