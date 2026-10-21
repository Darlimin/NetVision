from __future__ import annotations

import csv
import ctypes
from dataclasses import asdict, fields, is_dataclass
import hashlib
import json
import ipaddress
from io import StringIO
import locale
import os
import platform
import re
import secrets
from collections.abc import Iterable, Mapping
from urllib.parse import urlsplit, urlunsplit

from netvision.models import DiagnosticReport


UDP_EVENT_COLUMNS = (
    "timestamp",
    "event_type",
    "port",
    "details",
    "is_anomaly",
    "pid",
)

JOURNAL_EVENT_COLUMNS = (
    "id",
    "session",
    "at",
    "layer",
    "kind",
    "severity",
    "subject",
    "template",
    "values",
    "refs",
)

SUPPORT_BUNDLE_SECTIONS = ("report", "session", "measurements", "process", "history")
_MAC_PATTERN = re.compile(r"(?i)(?<![0-9a-f])(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}(?![0-9a-f])")
_IPV4_PATTERN = re.compile(r"(?<![0-9a-z])(?:\d{1,3}\.){3}\d{1,3}(?![0-9a-z])", re.IGNORECASE)


def serialize_report(report: DiagnosticReport, udp_events: Iterable[object] = ()) -> str:
    """Serialize the complete diagnostic report and optional UDP session history."""

    payload = asdict(report)
    udp_event_rows = serialize_udp_events(udp_events)
    payload["schema_version"] = "1.1"
    payload["system"]["proxies"] = [
        [scheme, _redact_proxy_credentials(value)]
        for scheme, value in report.system.proxies
    ]
    payload["udp_activity"] = {
        "event_count": len(udp_event_rows),
        "events": udp_event_rows,
    }
    return json.dumps(payload, ensure_ascii=False, indent=2, default=_json_default)


def serialize_support_bundle(
    report: DiagnosticReport | None = None,
    *,
    journal: object | None = None,
    session: object | None = None,
    journal_events: Iterable[object] = (),
    thresholds: object | None = None,
    measurements: Mapping[str, object] | None = None,
    process: object | None = None,
    endpoints: Iterable[object] = (),
    history: Iterable[Mapping[str, object]] = (),
    sections: Iterable[str] | None = None,
    app_version: str | None = None,
    redact: bool = True,
    max_events: int = 5000,
) -> str:
    """Serialize a support bundle without exposing raw process or traffic data."""

    selected_sections = set(SUPPORT_BUNDLE_SECTIONS if sections is None else sections)
    selected_sections.intersection_update(SUPPORT_BUNDLE_SECTIONS)
    event_limit = max(0, int(max_events))
    active_journal = journal or session
    if active_journal is not None and callable(getattr(active_journal, "export", None)):
        raw_events = active_journal.export()
    else:
        raw_events = [_support_jsonable(event) for event in journal_events]
    events = [_support_jsonable(event) for event in list(raw_events)[-event_limit:]]
    threshold_payload = _support_jsonable(thresholds) if thresholds is not None else {}

    payload: dict[str, object] = {
        "schema_version": "1.2",
        "meta": _support_meta(app_version),
    }
    if "report" in selected_sections:
        payload["report"] = (
            json.loads(serialize_report(report)) if report is not None else None
        )
    if "session" in selected_sections:
        payload["session"] = {"events": events, "thresholds": threshold_payload}
    if "measurements" in selected_sections:
        payload["measurements"] = _support_jsonable(dict(measurements or {}))
    if "process" in selected_sections:
        payload["process"] = _support_process_payload(process, endpoints)
    if "history" in selected_sections:
        payload["history"] = [_support_jsonable(item) for item in history]

    if redact:
        payload = _SupportRedactor().apply(payload)
    return json.dumps(payload, ensure_ascii=False, indent=2, default=_json_default)


def _support_meta(app_version: str | None) -> dict[str, object]:
    if app_version is None:
        try:
            from netvision.version import display_version

            app_version = display_version()
        except (ImportError, AttributeError):
            app_version = "unknown"
    try:
        import PySide6

        pyside_version = str(getattr(PySide6, "__version__", "unknown"))
    except ImportError:
        pyside_version = "unavailable"
    try:
        is_admin = bool(ctypes.windll.shell32.IsUserAnAdmin()) if os.name == "nt" else False
    except (AttributeError, OSError):
        is_admin = False
    try:
        codepage = int(ctypes.windll.kernel32.GetOEMCP()) if os.name == "nt" else 0
    except (AttributeError, OSError):
        codepage = 0
    return {
        "netvision_version": app_version,
        "windows_version": platform.platform(),
        "python_version": platform.python_version(),
        "pyside6_version": pyside_version,
        "is_admin": is_admin,
        "oem_codepage": f"cp{codepage}" if codepage else locale.getpreferredencoding(False),
        "hostname": platform.node(),
    }


def _support_process_payload(process: object | None, endpoints: Iterable[object]) -> dict[str, object] | None:
    if process is None:
        return None
    if isinstance(process, Mapping):
        name = process.get("name")
        pid = process.get("pid")
        connections = process.get("connections", ())
    else:
        name = getattr(process, "name", None)
        pid = getattr(process, "pid", None)
        connections = getattr(process, "connections", ())
    selected = tuple(endpoints)
    if not selected:
        selected = tuple(connections or ())
    return {
        "name": str(name or ""),
        "pid": pid if isinstance(pid, int) else None,
        "endpoints": [_support_endpoint_payload(item) for item in selected],
    }


def _support_endpoint_payload(endpoint: object) -> dict[str, object]:
    if isinstance(endpoint, Mapping):
        get = endpoint.get
    else:
        get = lambda key, default=None: getattr(endpoint, key, default)
    return {
        "protocol": str(get("protocol", "")),
        "local_port": get("local_port"),
        "remote_address": get("remote_address"),
        "remote_port": get("remote_port"),
        "status": str(get("status", "")),
    }


def _support_jsonable(value: object) -> object:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, Mapping):
        return {str(key): _support_jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_support_jsonable(item) for item in value]
    if is_dataclass(value):
        return {field.name: _support_jsonable(getattr(value, field.name)) for field in fields(value)}
    slots = getattr(type(value), "__slots__", ())
    if isinstance(slots, str):
        slots = (slots,)
    if slots:
        return {
            name: _support_jsonable(getattr(value, name))
            for name in slots
            if hasattr(value, name)
        }
    isoformat = getattr(value, "isoformat", None)
    if callable(isoformat):
        return str(isoformat())
    return str(value)


class _SupportRedactor:
    def __init__(self) -> None:
        self._salt = secrets.token_bytes(32)
        self._tokens: dict[tuple[str, str], str] = {}
        self._used: dict[str, set[int]] = {}

    def apply(self, value: object, key: str = "") -> object:
        if isinstance(value, Mapping):
            return {
                str(name): self.apply(item, str(name))
                for name, item in value.items()
            }
        if isinstance(value, list):
            return [self.apply(item, key) for item in value]
        if isinstance(value, str):
            return self._redact_string(value, key)
        return value

    def _redact_string(self, value: str, key: str) -> str:
        normalized_key = key.casefold()
        if normalized_key in {"ssid"}:
            return self._token("ssid", value)
        if normalized_key in {"bssid"}:
            return self._token("bssid", value)
        if normalized_key in {"mac", "mac_address", "macaddress"}:
            return self._token("mac", value)
        if normalized_key in {"hostname", "computer_name", "computername"}:
            return self._token("host", value)
        if _MAC_PATTERN.fullmatch(value.strip()):
            return self._token("mac", value)
        try:
            address = ipaddress.ip_address(value.strip())
        except ValueError:
            address = None
        if address is not None and address.is_global:
            return self._token("ip", value.strip())

        def replace_ip(match: re.Match[str]) -> str:
            candidate = match.group(0)
            try:
                parsed = ipaddress.ip_address(candidate)
            except ValueError:
                return candidate
            return self._token("ip", candidate) if parsed.is_global else candidate

        redacted = _IPV4_PATTERN.sub(replace_ip, value)
        return _MAC_PATTERN.sub(lambda match: self._token("mac", match.group(0)), redacted)

    def _token(self, category: str, value: str) -> str:
        key = (category, value)
        existing = self._tokens.get(key)
        if existing is not None:
            return existing
        digest = hashlib.blake2b(
            f"{category}:{value}".encode("utf-8"), key=self._salt, digest_size=8
        ).digest()
        candidate = int.from_bytes(digest, "big") % 1_000_000 + 1
        used = self._used.setdefault(category, set())
        while candidate in used:
            candidate = candidate % 1_000_000 + 1
        used.add(candidate)
        token = f"{category}-{candidate}"
        self._tokens[key] = token
        return token


def serialize_udp_events(events: Iterable[object]) -> list[dict[str, object]]:
    """Return a portable, UI-independent representation of UDP event rows."""

    return [_udp_event_payload(event) for event in events]


def serialize_udp_events_json(events: Iterable[object]) -> str:
    payload = {
        "schema_version": "1.0",
        "udp_activity": {
            "event_count": 0,
            "events": serialize_udp_events(events),
        },
    }
    payload["udp_activity"]["event_count"] = len(payload["udp_activity"]["events"])
    return json.dumps(payload, ensure_ascii=False, indent=2)


def serialize_udp_events_csv(events: Iterable[object]) -> str:
    output = StringIO(newline="")
    writer = csv.DictWriter(output, fieldnames=UDP_EVENT_COLUMNS, lineterminator="\n")
    writer.writeheader()
    writer.writerows(serialize_udp_events(events))
    return output.getvalue()


def serialize_journal_json(events: Iterable[object]) -> str:
    """Serialize journal records without importing the journal model here."""

    rows = [_journal_event_payload(event) for event in events]
    return json.dumps(
        {"schema_version": "1.0", "event_journal": {"event_count": len(rows), "events": rows}},
        ensure_ascii=False,
        indent=2,
        default=_json_default,
    )


def serialize_journal_csv(events: Iterable[object]) -> str:
    output = StringIO(newline="")
    writer = csv.DictWriter(output, fieldnames=JOURNAL_EVENT_COLUMNS, lineterminator="\n")
    writer.writeheader()
    writer.writerows(_journal_event_payload(event) for event in events)
    return output.getvalue()


def _udp_event_payload(event: object) -> dict[str, object]:
    observed_at = getattr(event, "observed_at", None)
    isoformat = getattr(observed_at, "isoformat", None)
    timestamp = str(isoformat()) if callable(isoformat) else str(observed_at or "")
    port = getattr(event, "port", None)
    return {
        "timestamp": timestamp,
        "event_type": str(getattr(event, "event_type", "")),
        "port": port if isinstance(port, int) else None,
        "details": str(getattr(event, "details", "")),
        "is_anomaly": bool(getattr(event, "is_anomaly", False)),
        "pid": getattr(event, "pid", None) if isinstance(getattr(event, "pid", None), int) else None,
    }


def _journal_event_payload(event: object) -> dict[str, object]:
    at = getattr(event, "at", None)
    isoformat = getattr(at, "isoformat", None)
    layer = getattr(event, "layer", "")
    layer_value = getattr(layer, "value", layer)
    values = getattr(event, "values", {})
    refs = getattr(event, "refs", {})
    return {
        "id": str(getattr(event, "id", "")),
        "session": str(getattr(event, "session", "")),
        "at": str(isoformat()) if callable(isoformat) else str(at or ""),
        "layer": str(layer_value),
        "kind": str(getattr(event, "kind", "")),
        "severity": str(getattr(event, "severity", "")),
        "subject": str(getattr(event, "subject", "")),
        "template": str(getattr(event, "template", "")),
        "values": json.dumps(values if isinstance(values, dict) else {}, ensure_ascii=False, default=_json_default),
        "refs": json.dumps(refs if isinstance(refs, dict) else {}, ensure_ascii=False, default=_json_default),
    }


def _redact_proxy_credentials(value: str) -> str:
    try:
        parsed = urlsplit(value)
        if not parsed.scheme or not parsed.netloc or "@" not in parsed.netloc:
            return value
        host = parsed.hostname
        if not host:
            return "<proxy configured>"
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
        port = f":{parsed.port}" if parsed.port is not None else ""
        return urlunsplit((parsed.scheme, f"{host}{port}", parsed.path, parsed.query, parsed.fragment))
    except ValueError:
        return "<proxy configured>"


def _json_default(value: object) -> str:
    isoformat = getattr(value, "isoformat", None)
    if callable(isoformat):
        return str(isoformat())
    return str(value)

