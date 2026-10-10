from __future__ import annotations

import csv
import json
from dataclasses import asdict
from io import StringIO
from collections.abc import Iterable
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

