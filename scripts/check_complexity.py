"""Check McCabe complexity only for functions changed relative to ``HEAD``."""

from __future__ import annotations

import ast
from dataclasses import dataclass
import json
from pathlib import Path
import re
import subprocess
import sys
from collections.abc import Sequence

ROOT = Path(__file__).resolve().parents[1]
_HUNK_PATTERN = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")
_QUALITY_DIRECTORIES = frozenset({"netvision", "scripts", "tests"})


@dataclass(frozen=True, slots=True)
class ChangedPythonFile:
    path: Path
    changed_lines: frozenset[int] | None


def _git_output(*arguments: str) -> str:
    completed = subprocess.run(
        ["git", *arguments],
        cwd=ROOT,
        capture_output=True,
        check=False,
        encoding="utf-8",
        text=True,
    )
    if completed.returncode:
        message = completed.stderr.strip() or "git command failed"
        raise RuntimeError(message)
    return completed.stdout


def _changed_python_files() -> tuple[ChangedPythonFile, ...]:
    _git_output("rev-parse", "--verify", "HEAD")
    diff = _git_output("diff", "--no-ext-diff", "--unified=0", "HEAD", "--", "*.py")
    changed = _parse_changed_lines(diff)
    untracked = _git_output("ls-files", "--others", "--exclude-standard", "--", "*.py")
    for relative_path in untracked.splitlines():
        path = (ROOT / relative_path).resolve()
        if path.is_file():
            changed[path] = None
    return tuple(
        ChangedPythonFile(path, lines)
        for path, lines in sorted(changed.items(), key=lambda item: str(item[0]).casefold())
        if path.is_file() and _is_quality_target(path)
    )


def _explicit_python_files(arguments: Sequence[str]) -> tuple[ChangedPythonFile, ...]:
    files: list[ChangedPythonFile] = []
    for value in arguments:
        path = Path(value)
        path = path if path.is_absolute() else ROOT / path
        path = path.resolve()
        if not path.is_file():
            raise RuntimeError(f"Python file not found: {value}")
        if path.suffix.casefold() != ".py" or not _is_quality_target(path):
            raise RuntimeError(f"Path is outside the quality Python scope: {value}")
        files.append(ChangedPythonFile(path, None))
    return tuple(files)


def _parse_changed_lines(diff: str) -> dict[Path, frozenset[int]]:
    changed: dict[Path, set[int]] = {}
    current_path: Path | None = None
    for line in diff.splitlines():
        if line.startswith("+++ "):
            current_path = _path_from_diff_header(line)
            continue
        match = _HUNK_PATTERN.match(line)
        if match is None or current_path is None:
            continue
        start = int(match.group(1))
        count = int(match.group(2) or 1)
        changed.setdefault(current_path, set()).update(range(start, start + count))
    return {path: frozenset(lines) for path, lines in changed.items()}


def _path_from_diff_header(line: str) -> Path | None:
    value = line.removeprefix("+++ ").strip()
    if value == "/dev/null":
        return None
    if value.startswith("b/"):
        value = value[2:]
    return (ROOT / value).resolve()


def _is_quality_target(path: Path) -> bool:
    try:
        relative_path = path.relative_to(ROOT)
    except ValueError:
        return False
    return bool(relative_path.parts) and relative_path.parts[0] in _QUALITY_DIRECTORIES


def _changed_function_lines(item: ChangedPythonFile) -> frozenset[int]:
    source = item.path.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(item.path))
    functions = (
        node for node in ast.walk(tree) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    )
    if item.changed_lines is None:
        return frozenset(node.lineno for node in functions)
    return frozenset(
        node.lineno for node in functions if _function_intersects_changes(node, item.changed_lines)
    )


def _function_intersects_changes(
    function: ast.FunctionDef | ast.AsyncFunctionDef, changed_lines: frozenset[int]
) -> bool:
    end_line = function.end_lineno or function.lineno
    return any(function.lineno <= line <= end_line for line in changed_lines)


def _ruff_diagnostics(paths: tuple[Path, ...]) -> list[dict[str, object]]:
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "ruff",
            "check",
            "--select",
            "C901",
            "--output-format",
            "json",
            *(str(path) for path in paths),
        ],
        cwd=ROOT,
        capture_output=True,
        check=False,
        encoding="utf-8",
        text=True,
    )
    if completed.returncode not in {0, 1}:
        message = completed.stderr.strip() or completed.stdout.strip() or "ruff check failed"
        raise RuntimeError(message)
    return json.loads(completed.stdout or "[]")


def _diagnostics_for_changed_functions(
    files: tuple[ChangedPythonFile, ...], diagnostics: list[dict[str, object]]
) -> list[dict[str, object]]:
    changed_functions = {item.path: _changed_function_lines(item) for item in files}
    failures: list[dict[str, object]] = []
    for diagnostic in diagnostics:
        path = _diagnostic_path(diagnostic)
        location = diagnostic.get("location", {})
        line = location.get("row") if isinstance(location, dict) else None
        if isinstance(line, int) and line in changed_functions.get(path, frozenset()):
            failures.append(diagnostic)
    return failures


def _diagnostic_path(diagnostic: dict[str, object]) -> Path:
    filename = Path(str(diagnostic["filename"]))
    return filename.resolve() if filename.is_absolute() else (ROOT / filename).resolve()


def _display_diagnostic(diagnostic: dict[str, object]) -> str:
    path = _diagnostic_path(diagnostic)
    try:
        display_path = path.relative_to(ROOT)
    except ValueError:
        display_path = path
    location = diagnostic.get("location", {})
    line = location.get("row", "?") if isinstance(location, dict) else "?"
    return f"{display_path}:{line}: {diagnostic['message']}"


def main(arguments: Sequence[str] | None = None) -> int:
    arguments = sys.argv[1:] if arguments is None else arguments
    scope_name = "selected" if arguments else "changed"
    try:
        files = _explicit_python_files(arguments) if arguments else _changed_python_files()
        if not files:
            print("No changed Python files to inspect for C901.")
            return 0
        diagnostics = _ruff_diagnostics(tuple(item.path for item in files))
        failures = _diagnostics_for_changed_functions(files, diagnostics)
    except (OSError, RuntimeError, SyntaxError, json.JSONDecodeError) as exc:
        print(f"Complexity check failed: {exc}", file=sys.stderr)
        return 2
    if failures:
        print("C901 complexity violations in changed functions:", file=sys.stderr)
        for diagnostic in failures:
            print(_display_diagnostic(diagnostic), file=sys.stderr)
        return 1
    function_count = sum(len(_changed_function_lines(item)) for item in files)
    print(
        f"C901 passed for {function_count} {scope_name} function(s) in {len(files)} Python file(s)."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
