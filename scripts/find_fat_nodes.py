"""List the ten largest source-spanning AST nodes in the dashboard."""

import ast
from pathlib import Path


def main() -> None:
    path = Path(__file__).resolve().parent.parent / "netvision/ui/dashboard_v2.py"
    tree = ast.parse(path.read_text(encoding="utf-8"))
    kinds = (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef, ast.Assign, ast.AnnAssign)
    nodes = [
        node for node in ast.walk(tree) if isinstance(node, kinds) and node.end_lineno is not None
    ]
    nodes.sort(key=lambda node: (-(node.end_lineno - node.lineno + 1), node.lineno))
    for node in nodes[:10]:
        name = getattr(node, "name", "")
        if isinstance(node, ast.Assign):
            name = ", ".join(ast.unparse(target) for target in node.targets)
        elif isinstance(node, ast.AnnAssign):
            name = ast.unparse(node.target)
        print(
            f"{node.end_lineno - node.lineno + 1:5} lines  {type(node).__name__:16} {name}  line {node.lineno}"
        )


if __name__ == "__main__":
    main()
