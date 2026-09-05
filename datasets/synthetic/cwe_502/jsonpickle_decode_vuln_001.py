"""CWE-502: jsonpickle.decode on user input — VULNERABLE.
Edge case: jsonpickle serialises Python objects as JSON, so it *looks*
like safe JSON handling.  However, jsonpickle.decode can instantiate
arbitrary classes, making it as dangerous as pickle.loads.
"""

from typing import Any

import jsonpickle


class AnalyticsEvent:
    """Domain object representing an analytics event."""

    def __init__(self, name: str, properties: dict[str, Any]) -> None:
        self.name = name
        self.properties = properties

    def __repr__(self) -> str:
        return f"AnalyticsEvent({self.name!r})"


def ingest_event(json_payload: str) -> AnalyticsEvent:
    """Deserialize an analytics event from a JSON string.

    Called by the web framework with the raw request body.
    """
    obj = jsonpickle.decode(json_payload)  # VULNERABLE: arbitrary instantiation
    if not isinstance(obj, AnalyticsEvent):
        raise TypeError(f"Expected AnalyticsEvent, got {type(obj).__name__}")
    return obj


def batch_ingest(payloads: list[str]) -> list[AnalyticsEvent]:
    events: list[AnalyticsEvent] = []
    for payload in payloads:
        try:
            events.append(ingest_event(payload))
        except (TypeError, ValueError):
            continue
    return events
