import ast
import os
import sys
from collections import defaultdict
from difflib import SequenceMatcher

ENTRY_POINT_DECORATORS = {
    "Slot",
    "pyqtSlot",
    "route",
    "get",
    "post",
    "task",
    "callback",
    "event",
    "abstractmethod",
    "property",
    "staticmethod",
    "classmethod",
}

QT_IMPLICIT_METHODS = {
    "__init__",
    "__del__",
    "__enter__",
    "__exit__",
    "__repr__",
    "__str__",
    "paintEvent",
    "resizeEvent",
    "closeEvent",
    "showEvent",
    "mousePressEvent",
    "mouseMoveEvent",
    "mouseReleaseEvent",
    "keyPressEvent",
    "timerEvent",
    "run",
}

IGNORE_DIRS = {
    ".git",
    ".venv",
    "venv",
    "__pycache__",
    ".pytest_cache",
    ".ruff_cache",
    "build",
    "dist",
    ".build-dist",
    ".build-spec",
    ".build-dist-0.8.0",
    ".build-spec-0.8.0",
    ".build-argcheck-spec",
}


class DeepPythonAuditor(ast.NodeVisitor):
    def __init__(self):
        self.funcs = {}
        self.call_graph = defaultdict(set)
        self.referenced_names = set()

        self.current_file = ""
        self.current_class = None
        self.current_func = None

    def _normalize_node(self, node):
        """Строит структурный 'скелет' кода, игнорируя имена локальных переменных."""
        if isinstance(node, ast.AST):
            if (
                isinstance(node, ast.Expr)
                and isinstance(node.value, ast.Constant)
                and isinstance(node.value.value, str)
            ):
                return ""
            fields = []
            for k, v in ast.iter_fields(node):
                if k in ("id", "arg", "name", "value", "lineno", "col_offset", "ctx"):
                    continue
                fields.append(f"{k}={self._normalize_node(v)}")
            return f"{node.__class__.__name__}({','.join(fields)})"
        elif isinstance(node, list):
            return f"[{','.join(self._normalize_node(x) for x in node if self._normalize_node(x))}]"
        return str(node)

    def _extract_api_footprint(self, node):
        """Извлекает набор вызываемых внешних функций/методов внутри функции."""
        apis = set()
        for subnode in ast.walk(node):
            if isinstance(subnode, ast.Call):
                if isinstance(subnode.func, ast.Name):
                    apis.add(subnode.func.id)
                elif isinstance(subnode.func, ast.Attribute):
                    apis.add(subnode.func.attr)
        return apis

    def visit_ClassDef(self, node):
        prev_class = self.current_class
        self.current_class = node.name
        self.generic_visit(node)
        self.current_class = prev_class

    def visit_FunctionDef(self, node):
        self._process_function(node)

    def visit_AsyncFunctionDef(self, node):
        self._process_function(node)

    def _process_function(self, node):
        qual_name = f"{self.current_class}.{node.name}" if self.current_class else node.name
        fid = f"{self.current_file}:{qual_name}:{node.lineno}"

        # Проверяем декораторы (@Slot и т.д.)
        decorators = set()
        for dec in node.decorator_list:
            if isinstance(dec, ast.Name):
                decorators.add(dec.id)
            elif isinstance(dec, ast.Attribute):
                decorators.add(dec.attr)
            elif isinstance(dec, ast.Call):
                if isinstance(dec.func, ast.Name):
                    decorators.add(dec.func.id)
                elif isinstance(dec.func, ast.Attribute):
                    decorators.add(dec.func.attr)

        is_entry = (
            bool(decorators & ENTRY_POINT_DECORATORS)
            or node.name in QT_IMPLICIT_METHODS
            or node.name.startswith("test_")
        )

        end_line = getattr(node, "end_lineno", node.lineno)
        self.funcs[fid] = {
            "name": node.name,
            "qual_name": qual_name,
            "file": self.current_file,
            "line": node.lineno,
            "lines_count": max(1, end_line - node.lineno + 1),
            "is_entry": is_entry,
            "norm_ast": self._normalize_node(node.body),
            "apis": self._extract_api_footprint(node),
        }

        prev_func = self.current_func
        self.current_func = node.name
        self.generic_visit(node)
        self.current_func = prev_func

    def visit_Call(self, node):
        self._remember_reference(_node_name(node.func))
        for argument in (*node.args, *(keyword.value for keyword in node.keywords)):
            self._remember_reference(_node_name(argument))
        self.generic_visit(node)

    def _remember_reference(self, name):
        if name:
            self.referenced_names.add(name)
            if self.current_func:
                self.call_graph[self.current_func].add(name)

    def visit_Attribute(self, node):
        # Учет ссылок вида self.my_callback в словарях/списках диспетчеризации
        if isinstance(node.ctx, ast.Load):
            self.referenced_names.add(node.attr)
        self.generic_visit(node)


def run_audit(target_dir=".", struct_threshold=0.82, api_threshold=0.75):
    auditor = DeepPythonAuditor()
    target_dir = os.path.abspath(target_dir)
    _visit_python_files(auditor, target_dir)
    _print_dead_code(auditor)
    _print_orphaned_chains(auditor)
    _print_clones(auditor, struct_threshold, api_threshold)


def _node_name(node):
    if isinstance(node, (ast.Name, ast.Attribute)):
        return node.id if isinstance(node, ast.Name) else node.attr
    return None


def _visit_python_files(auditor, target_dir):
    self_name = os.path.basename(__file__)
    for root, dirs, files in os.walk(target_dir):
        dirs[:] = [
            directory
            for directory in dirs
            if directory not in IGNORE_DIRS and not directory.startswith(".build")
        ]
        for filename in files:
            if filename.endswith(".py") and filename != self_name:
                _visit_python_file(auditor, target_dir, os.path.join(root, filename))


def _visit_python_file(auditor, target_dir, path):
    auditor.current_file = os.path.relpath(path, target_dir)
    try:
        with open(path, "r", encoding="utf-8") as file_obj:
            auditor.visit(ast.parse(file_obj.read(), filename=path))
    except SyntaxError as error:
        print(f"[WARN] Ошибка синтаксиса в {path}: {error}")


def _print_dead_code(auditor):
    print("=" * 75)
    print(" 1. РУДИМЕНТЫ И МЕРТВЫЕ ФУНКЦИИ (Включая невызываемые Callbacks)")
    print("=" * 75)
    dead_names = set()
    for fid, data in auditor.funcs.items():
        name = data["name"]
        if not data["is_entry"] and name not in auditor.referenced_names:
            print(
                f"  [DEAD] {data['qual_name']:<35} | {data['file']}:{data['line']} ({data['lines_count']} строк)"
            )
            dead_names.add(name)
    return dead_names


def _print_orphaned_chains(auditor):
    print("\n--- Осиротевшие цепочки (вызываются только из мертвого кода) ---")
    dead_names = {
        data["name"]
        for data in auditor.funcs.values()
        if not data["is_entry"] and data["name"] not in auditor.referenced_names
    }
    for fid, data in auditor.funcs.items():
        name = data["name"]
        if name in dead_names or data["is_entry"]:
            continue
        callers = {caller for caller, callees in auditor.call_graph.items() if name in callees}
        if callers and callers.issubset(dead_names):
            print(
                f"  [ORPHAN] {data['qual_name']:<33} | Вызывается только из рудиментов: "
                f"{', '.join(callers)} ({data['file']}:{data['line']})"
            )


def _print_clones(auditor, struct_threshold, api_threshold):
    print("\n" + "=" * 75)
    print(" 2. СТРУКТУРНЫЕ И СМЫСЛОВЫЕ ДУБЛИКАТЫ (Клоны логики и API)")
    print("=" * 75)
    func_items = list(auditor.funcs.items())
    for i in range(len(func_items)):
        for j in range(i + 1, len(func_items)):
            id1, f1 = func_items[i]
            id2, f2 = func_items[j]

            if f1["lines_count"] < 6 or f2["lines_count"] < 6:
                continue

            ast_ratio = SequenceMatcher(None, f1["norm_ast"], f2["norm_ast"]).ratio()

            apis1, apis2 = f1["apis"], f2["apis"]
            if len(apis1) >= 3 and len(apis2) >= 3:
                intersection = len(apis1 & apis2)
                union = len(apis1 | apis2)
                api_ratio = intersection / union if union else 0.0
            else:
                api_ratio = 0.0

            if ast_ratio >= struct_threshold or api_ratio >= api_threshold:
                reason = []
                if ast_ratio >= struct_threshold:
                    reason.append(f"Структура: {ast_ratio * 100:.0f}%")
                if api_ratio >= api_threshold:
                    common = ", ".join(list(apis1 & apis2)[:4])
                    reason.append(f"Общие вызовы ({api_ratio * 100:.0f}%): [{common}...]")

                print(
                    f"  [CLONE] {f1['qual_name']} ({f1['file']}:{f1['line']}) <===> {f2['qual_name']} ({f2['file']}:{f2['line']})"
                )
                print(f"          Причина: {' | '.join(reason)}\n")


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "."
    run_audit(target)
