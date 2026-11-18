from importlib.util import module_from_spec, spec_from_file_location
import os
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


def test_build_environment_excludes_unrelated_icu(tmp_path: Path) -> None:
    script = Path(__file__).resolve().parents[1] / "scripts" / "build_release.py"
    spec = spec_from_file_location("netvision_build_environment", script)
    assert spec is not None and spec.loader is not None
    builder = module_from_spec(spec)
    spec.loader.exec_module(builder)
    unrelated = tmp_path / "poppler"
    unrelated.mkdir()
    (unrelated / "icuuc.dll").touch()
    safe = tmp_path / "other"
    safe.mkdir()
    with patch.dict(os.environ, {"PATH": os.pathsep.join([str(unrelated), str(safe)])}):
        assert builder.build_environment()["PATH"] == str(safe)


def test_release_builder_includes_native_extension_and_assets(tmp_path: Path) -> None:
    script = Path(__file__).resolve().parents[1] / "scripts" / "build_release.py"
    spec = spec_from_file_location("netvision_build_release", script)
    assert spec is not None and spec.loader is not None
    builder = module_from_spec(spec)
    spec.loader.exec_module(builder)
    native = tmp_path / "netvision_rs.cp312-win_amd64.pyd"
    extension = SimpleNamespace(origin=str(native))
    module = SimpleNamespace(parse_ping_output=lambda _: [], parse_tracert_rows=lambda _: [])
    with (
        patch.object(builder.sys, "platform", "win32"),
        patch.dict("sys.modules", {"netvision_rs": module}),
        patch.object(builder.importlib.util, "find_spec", side_effect=[object(), extension]),
        patch.object(builder.inspect, "getsource", return_value="codex-rejected-cas.pem"),
        patch.object(builder.ssl, "__file__", str(tmp_path / "ssl.py")),
        patch.object(builder.subprocess, "call", return_value=0) as call,
    ):
        (tmp_path / "codex-rejected-cas.pem").write_text("test", encoding="utf-8")
        assert builder.main() == 0
    command = call.call_args.args[0]
    assert "--windowed" in command
    assert "--console" not in command
    assert "--collect-all" in command
    assert "netvision_rs" in command
    assert f"{native};netvision_rs" in command
    assert any("ru-ru.json" in arg for arg in command)
    assert any("en-en.json" in arg for arg in command)
    assert any("fonts" in arg for arg in command)
    assert f"{tmp_path / 'codex-rejected-cas.pem'};." in command


def test_release_builder_does_not_require_custom_ca_file_for_standard_python(
    tmp_path: Path,
) -> None:
    script = Path(__file__).resolve().parents[1] / "scripts" / "build_release.py"
    spec = spec_from_file_location("netvision_build_release_standard", script)
    assert spec is not None and spec.loader is not None
    builder = module_from_spec(spec)
    spec.loader.exec_module(builder)
    native = tmp_path / "netvision_rs.cp312-win_amd64.pyd"
    module = SimpleNamespace(parse_ping_output=lambda _: [], parse_tracert_rows=lambda _: [])
    with (
        patch.object(builder.sys, "platform", "win32"),
        patch.dict("sys.modules", {"netvision_rs": module}),
        patch.object(
            builder.importlib.util,
            "find_spec",
            side_effect=[object(), SimpleNamespace(origin=str(native))],
        ),
        patch.object(builder.inspect, "getsource", return_value="standard SSLContext"),
        patch.object(builder.subprocess, "call", return_value=0) as call,
    ):
        assert builder.main() == 0
    assert not any("codex-rejected-cas.pem" in arg for arg in call.call_args.args[0])
