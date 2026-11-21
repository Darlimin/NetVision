"""Build a Windows release with an explicit Rust extension and UI assets."""

from __future__ import annotations

import importlib.machinery
import importlib.util
import inspect
import os
import ssl
from datetime import datetime
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parent.parent


def build_environment() -> dict[str, str]:
    """Keep unrelated ICU DLLs out of PyInstaller's dependency search path."""
    env = os.environ.copy()
    system_dir = Path(env.get("SystemRoot", r"C:\Windows")) / "System32"
    paths = env.get("PATH", "").split(os.pathsep)
    safe_paths = []
    for entry in paths:
        directory = Path(entry)
        if (
            entry
            and (directory / "icuuc.dll").is_file()
            and directory.resolve() != system_dir.resolve()
        ):
            print(f"Excluding ICU DLL directory from build PATH: {entry}", flush=True)
            continue
        safe_paths.append(entry)
    env["PATH"] = os.pathsep.join(safe_paths)
    return env


def main() -> int:
    if sys.platform != "win32":
        print("Build this Windows release on Windows.", file=sys.stderr)
        return 1
    if importlib.util.find_spec("PyInstaller") is None:
        print(
            "Install PyInstaller in this environment: python -m pip install pyinstaller",
            file=sys.stderr,
        )
        return 1
    import netvision_rs

    if not all(
        callable(getattr(netvision_rs, name, None))
        for name in ("parse_ping_output", "parse_tracert_rows")
    ):
        print("Rebuild netvision_rs with maturin develop before packaging.", file=sys.stderr)
        return 1
    native_spec = importlib.util.find_spec("netvision_rs.netvision_rs")
    if (
        native_spec is None
        or not native_spec.origin
        or not any(
            native_spec.origin.endswith(suffix) for suffix in importlib.machinery.EXTENSION_SUFFIXES
        )
    ):
        print("Cannot locate the compiled netvision_rs extension.", file=sys.stderr)
        return 1
    native_file = Path(native_spec.origin).resolve()
    ssl_source = inspect.getsource(ssl.SSLContext.__new__)
    rejected_ca_name = "codex-rejected-cas.pem"
    ssl_assets = []
    if rejected_ca_name in ssl_source:
        rejected_ca = Path(ssl.__file__).resolve().parent / rejected_ca_name
        if not rejected_ca.is_file():
            print(f"Required SSL policy file is missing: {rejected_ca}", file=sys.stderr)
            return 1
        ssl_assets = ["--add-data", f"{rejected_ca};."]
    run_id = datetime.now().strftime("%Y%m%d-%H%M%S-%f")
    output_root = ROOT / "release" / f"pyinstaller-{run_id}"
    cmd = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--onedir",
        "--windowed",
        *ssl_assets,
        "--name",
        "NetVision",
        "--distpath",
        str(output_root / "dist"),
        "--workpath",
        str(output_root / "work"),
        "--specpath",
        str(output_root),
        "--paths",
        str(ROOT),
        "--icon",
        str(ROOT / "NetVision.ico"),
        "--collect-all",
        "netvision_rs",
        "--hidden-import",
        "netvision_rs.netvision_rs",
        "--hidden-import",
        "PySide6.QtWebEngineWidgets",
        "--add-binary",
        f"{native_file};netvision_rs",
        "--add-data",
        f"{ROOT / 'fonts'};fonts",
        "--add-data",
        f"{ROOT / 'NetVision.ico'};.",
        "--add-data",
        f"{ROOT / 'netvision/ui/ru-ru.json'};netvision/ui",
        "--add-data",
        f"{ROOT / 'netvision/ui/en-en.json'};netvision/ui",
        "--add-data",
        f"{ROOT / 'netvision/ui/cyber_theme.qss'};netvision/ui",
        "--add-data",
        f"{ROOT / 'LICENSE'};.",
        "--add-data",
        f"{ROOT / 'NOTICE.txt'};.",
        "--add-data",
        f"{ROOT / 'EULA.txt'};.",
        str(ROOT / "netvision/__main__.py"),
    ]
    print(f"Rust extension: {native_file}", flush=True)
    print(f"Build output: {output_root}", flush=True)
    result = subprocess.call(cmd, cwd=ROOT, env=build_environment())
    if result == 0:
        internal = output_root / "dist" / "NetVision" / "_internal"
        for relative in (
            "PySide6/resources/qtwebengine_devtools_resources.debug.pak",
            "netvision_rs/netvision_rs.pdb",
        ):
            (internal / relative).unlink(missing_ok=True)
    return result


if __name__ == "__main__":
    raise SystemExit(main())
