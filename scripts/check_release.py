"""Pre-release checks that do not require network access or administrator rights."""

from __future__ import annotations

import argparse
import ast
import json
from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[1]
LOCALES = ("netvision/ui/ru-ru.json", "netvision/ui/en-en.json")
REQUIRED_FILES = (
    "README.md",
    "EULA.txt",
    "NOTICE.txt",
    "NetVision.ico",
    "netvision/__main__.py",
    "netvision/app.py",
    "fonts/static/Inter_18pt-Regular.ttf",
    "fonts/static/Inter_18pt-Medium.ttf",
    "fonts/static/Inter_18pt-SemiBold.ttf",
    "fonts/static/Inter_18pt-Bold.ttf",
)
NETWORK_THRESHOLD_VALUES = frozenset({10, 15, 25, 30, 80, 100, 150})
NETWORK_CONTEXT = re.compile(r"latency|jitter|rtt|ping|loss|spike|burst|delay", re.IGNORECASE)


def check_release(root: Path = ROOT) -> list[str]:
    """Return every release-readiness failure without invoking the application."""

    return [
        *check_localization_keys(root),
        *check_network_threshold_literals(root),
        *check_required_assets(root),
    ]


def check_localization_keys(root: Path) -> list[str]:
    catalogs: list[tuple[Path, dict[str, object]]] = []
    failures: list[str] = []
    for relative_path in LOCALES:
        path = root / relative_path
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            failures.append(f"Localization file is unavailable or invalid: {relative_path} ({error})")
            continue
        if not isinstance(payload, dict):
            failures.append(f"Localization catalog is not an object: {relative_path}")
            continue
        catalogs.append((path, payload))
    if len(catalogs) != 2:
        return failures
    (ru_path, ru_catalog), (en_path, en_catalog) = catalogs
    missing_in_en = sorted(set(ru_catalog) - set(en_catalog))
    missing_in_ru = sorted(set(en_catalog) - set(ru_catalog))
    if missing_in_en:
        failures.append(
            f"Missing {len(missing_in_en)} EN localization keys from {en_path.name}: "
            + ", ".join(missing_in_en)
        )
    if missing_in_ru:
        failures.append(
            f"Missing {len(missing_in_ru)} RU localization keys from {ru_path.name}: "
            + ", ".join(missing_in_ru)
        )
    return failures


def check_network_threshold_literals(root: Path) -> list[str]:
    """Find hardcoded latency/jitter/loss comparison thresholds in application code."""

    failures: list[str] = []
    source_root = root / "netvision"
    for path in source_root.rglob("*.py"):
        relative_path = path.relative_to(root).as_posix()
        if relative_path == "netvision/core/thresholds.py":
            continue
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except (OSError, UnicodeError, SyntaxError) as error:
            failures.append(f"Cannot parse {relative_path}: {error}")
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.Compare):
                continue
            expression = ast.unparse(node)
            if not NETWORK_CONTEXT.search(expression):
                continue
            values = [
                value.value
                for value in ast.walk(node)
                if isinstance(value, ast.Constant)
                and isinstance(value.value, (int, float))
                and value.value in NETWORK_THRESHOLD_VALUES
            ]
            if _is_full_packet_loss_comparison(expression, values):
                continue
            if values:
                failures.append(
                    f"Hardcoded network threshold in {relative_path}:{node.lineno} "
                    f"({', '.join(str(value) for value in values)}): {expression}"
                )
    return failures


def _is_full_packet_loss_comparison(expression: str, values: list[int | float]) -> bool:
    """100% packet loss is a terminal state, not a configurable threshold."""

    return "loss_percent" in expression and set(values) == {100}


def check_required_assets(root: Path) -> list[str]:
    return [
        f"Required release asset is missing: {relative_path}"
        for relative_path in REQUIRED_FILES
        if not (root / relative_path).is_file()
    ]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate NetVision release prerequisites.")
    parser.add_argument("--root", type=Path, default=ROOT, help="Project root directory")
    arguments = parser.parse_args(argv)
    failures = check_release(arguments.root.resolve())
    if failures:
        print("Release readiness check failed:")
        for failure in failures:
            print(f"- {failure}")
        return 1
    print("Release readiness check passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
