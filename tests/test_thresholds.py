from __future__ import annotations

import ast
from pathlib import Path

from netvision.core.thresholds import DEFAULT_THRESHOLDS, Thresholds


PROJECT_ROOT = Path(__file__).resolve().parents[1]
FORBIDDEN_THRESHOLD_LITERALS = {15, 100, 150}
SOURCE_FILES = tuple((PROJECT_ROOT / "netvision").rglob("*.py"))


def test_default_thresholds_match_current_network_quality_rules() -> None:
    assert DEFAULT_THRESHOLDS == Thresholds(
        jitter_spike_ms=15.0,
        jitter_critical_ms=25.0,
        jitter_bad_ms=30.0,
        jitter_clear_ms=10.0,
        rtt_high_ms=100.0,
        rtt_peak_ms=150.0,
        rtt_normal_ms=80.0,
        episode_quiet_samples=3,
    )


def test_network_threshold_comparisons_do_not_reintroduce_hardcoded_values() -> None:
    violations: list[str] = []
    for path in SOURCE_FILES:
        relative_path = path.relative_to(PROJECT_ROOT).as_posix()
        if relative_path == "netvision/core/thresholds.py":
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Compare):
                continue
            for left, right in zip((node.left, *node.comparators), node.comparators):
                literal, value = _threshold_literal(left, right)
                other = left if literal is right else right
                if value is None:
                    continue
                if _is_whitelisted_context(relative_path, other):
                    continue
                violations.append(f"{relative_path}:{node.lineno} ({value})")

    assert not violations, "Hardcoded network thresholds found: " + ", ".join(violations)


def _threshold_literal(left: ast.expr, right: ast.expr) -> tuple[ast.expr | None, int | None]:
    for candidate in (left, right):
        if isinstance(candidate, ast.Constant) and candidate.value in FORBIDDEN_THRESHOLD_LITERALS:
            return candidate, int(candidate.value)
    return None, None


def _is_whitelisted_context(relative_path: str, node: ast.expr) -> bool:
    source = ast.unparse(node)
    return (
        (relative_path.endswith("core/bufferbloat.py") and source == "value")
        or (
            relative_path.endswith("core/mtu_optimizer.py")
            and source in {"timeout_ms", "probe_timeout"}
        )
        or (
            relative_path.endswith("ui/main_window.py")
            and source in {"result.loss_percent", "report.ping.loss_percent"}
        )
    )
