from types import SimpleNamespace
from unittest.mock import patch

from netvision.core.rust_backend import rust_parser_availability


def test_rust_parser_availability_checks_each_function() -> None:
    module = SimpleNamespace(parse_ping_output=lambda value: value)
    with patch("netvision.core.rust_backend.import_module", return_value=module):
        assert rust_parser_availability() == (True, False)


def test_rust_parser_availability_handles_missing_extension() -> None:
    with patch("netvision.core.rust_backend.import_module", side_effect=ImportError):
        assert rust_parser_availability() == (False, False)
