"""Count lines connecting signals in the dashboard constructor."""

import ast
from pathlib import Path


def main() -> None:
    source = (Path(__file__).resolve().parent.parent / "netvision/ui/dashboard_v2.py").read_text(
        encoding="utf-8"
    )
    dashboard = next(
        node
        for node in ast.parse(source).body
        if isinstance(node, ast.ClassDef) and node.name == "NetVisionDashboardV2"
    )
    init = next(
        node
        for node in dashboard.body
        if isinstance(node, ast.FunctionDef) and node.name == "__init__"
    )
    count = sum(
        ".connect(" in line for line in source.splitlines()[init.lineno - 1 : init.end_lineno]
    )
    print(f"NetVisionDashboardV2.__init__: {count} lines containing .connect(")


if __name__ == "__main__":
    main()
