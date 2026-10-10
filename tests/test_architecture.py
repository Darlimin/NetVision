"""Keep the diagnostic core independent of Qt and the import graph acyclic."""
import ast
from importlib.util import resolve_name
from pathlib import Path


PACKAGE = Path(__file__).resolve().parents[1] / "netvision"


def module_imports(path):
    module = ".".join(path.relative_to(PACKAGE.parent).with_suffix("").parts)
    package = module.rpartition(".")[0]
    imports = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8-sig"))):
        if isinstance(node, ast.Import):
            imports.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            name = node.module or ""
            if node.level:
                name = resolve_name("." * node.level + name, package)
            imports.add(name)
            imports.update(f"{name}.{alias.name}" for alias in node.names)
    return module, imports


def test_core_does_not_depend_on_qt_or_ui():
    for path in (PACKAGE / "core").glob("*.py"):
        _, imports = module_imports(path)
        assert not any(name.startswith(("PySide", "PyQt", "netvision.ui")) for name in imports), path


def test_internal_imports_are_acyclic():
    modules = dict(module_imports(path) for path in PACKAGE.rglob("*.py"))
    visited = set()

    def visit(module, chain):
        assert module not in chain, " -> ".join((*chain, module))
        if module in visited:
            return
        for dependency in modules[module] & modules.keys():
            visit(dependency, (*chain, module))
        visited.add(module)

    for module in modules:
        visit(module, ())
