"""Shared protocol event helpers."""

from __future__ import annotations

from datetime import datetime, timezone


def event(sequence: int, protocol: str, direction: str, event_type: str,
          message: str, fields: dict[str, str], delay: int = 800,
          layer: str | None = None) -> dict:
    if layer is None:
        layer = "transport" if protocol in {"TCP", "UDP"} else "application"
    return {
        "sequence": sequence,
        "protocol": protocol,
        "layer": layer,
        "direction": direction,
        "type": event_type,
        "message": message,
        "fields": fields,
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
        "delay": delay,
    }
