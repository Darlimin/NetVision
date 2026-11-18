"""Map dashboard source lines using the Python AST."""

import ast
from pathlib import Path


def main() -> None:
    path = Path(__file__).resolve().parent.parent / "netvision/ui/dashboard_v2.py"
    source = path.read_text(encoding="utf-8")
    tree = ast.parse(source)
    classes = [n for n in ast.walk(tree) if isinstance(n, ast.ClassDef)]
    dashboard = next(n for n in classes if n.name == "NetVisionDashboardV2")
    methods = [n for n in dashboard.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
    properties = [
        n
        for n in methods
        if any(
            isinstance(d, ast.Name)
            and d.id == "property"
            or isinstance(d, ast.Attribute)
            and d.attr in {"setter", "deleter"}
            for d in n.decorator_list
        )
    ]
    class_data = [
        n
        for c in classes
        for n in c.body
        if isinstance(n, (ast.Assign, ast.AnnAssign))
        and isinstance(n.value, (ast.Dict, ast.List, ast.Set, ast.Tuple))
    ]
    module_data = [
        n
        for n in tree.body
        if isinstance(n, (ast.Import, ast.ImportFrom, ast.Assign, ast.AnnAssign))
    ]

    def count(nodes: list[ast.AST]) -> int:
        return sum(n.end_lineno - n.lineno + 1 for n in nodes)

    print(f"Всего строк: {len(source.splitlines())}")
    print(
        f"Свойства (@property и setter/deleter): {count(properties)} строк, {len(properties)} методов"
    )
    print(f"Коллекции уровня классов: {count(class_data)} строк, {len(class_data)} определений")
    print(
        f"Импорты и присваивания уровня модуля: {count(module_data)} строк, {len(module_data)} узлов"
    )
    print(f"Методы дашборда: {len(methods)}; сумма их диапазонов: {count(methods)} строк")
    print("Топ-5 методов дашборда:")
    for n in sorted(methods, key=lambda n: (-(n.end_lineno - n.lineno + 1), n.lineno))[:5]:
        print(f"  {n.name}: {n.end_lineno - n.lineno + 1} строк (строка {n.lineno})")
    print("Диапазоны методов включают внутренние пустые строки; декораторы в длину не входят.")


if __name__ == "__main__":
    main()
