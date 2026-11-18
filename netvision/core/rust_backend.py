"""Report availability of optional Rust parser functions."""

from importlib import import_module


def rust_parser_availability() -> tuple[bool, bool]:
    try:
        module = import_module("netvision_rs")
    except (ImportError, OSError):
        return False, False
    ping_available = callable(getattr(module, "parse_ping_output", None))
    tracert_available = callable(getattr(module, "parse_tracert_rows", None))
    return ping_available, tracert_available
