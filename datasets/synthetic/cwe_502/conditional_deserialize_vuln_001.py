"""CWE-502: Conditional deserialization — VULNERABLE.
Edge case: one branch uses safe json.loads, but the other branch uses
pickle.loads.  The unsafe branch is reachable when the user-supplied
content-type header is 'application/x-python-pickle'.
"""

import json
import pickle
from typing import Any


def parse_request_body(body: bytes, content_type: str) -> Any:
    """Dispatch deserialization based on content type."""
    if content_type == "application/json":
        return json.loads(body.decode("utf-8"))
    elif content_type == "application/x-python-pickle":
        return pickle.loads(body)  # VULNERABLE: reachable with user input
    else:
        raise ValueError(f"Unsupported content type: {content_type}")


class IngestEndpoint:
    """Simulated HTTP endpoint that accepts multiple serialization formats."""

    supported_types = ("application/json", "application/x-python-pickle")

    def handle(self, raw_body: bytes, headers: dict[str, str]) -> dict:
        ct = headers.get("Content-Type", "application/json")
        payload = parse_request_body(raw_body, ct)
        return {"status": "ok", "payload": payload}
