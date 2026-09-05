"""CWE-502: JSON with schema validation — SAFE.
Edge case: deserialization is performed, but only with json.loads, and
the result is validated against a strict JSON schema.  No pickle, yaml,
or marshal is used.  The word 'deserialize' appears frequently as a red
herring.
"""
import json
from typing import Any

EVENT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["event_type", "timestamp", "data"],
    "properties": {
        "event_type": {"type": "string", "enum": ["click", "view", "purchase"]},
        "timestamp": {"type": "number"},
        "data": {"type": "object"},
    },
    "additionalProperties": False,
}


def _validate(obj: Any, schema: dict[str, Any]) -> bool:
    """Minimal inline schema validation (subset of JSON Schema)."""
    if schema.get("type") == "object":
        if not isinstance(obj, dict):
            return False
        for req in schema.get("required", []):
            if req not in obj:
                return False
    return True


def deserialize_event(raw_payload: bytes) -> dict[str, Any]:
    """Safely deserialize and validate an analytics event."""
    deserialized = json.loads(raw_payload)
    if not _validate(deserialized, EVENT_SCHEMA):
        raise ValueError("Payload does not match expected schema")
    return deserialized


def batch_deserialize(payloads: list[bytes]) -> list[dict[str, Any]]:
    return [deserialize_event(p) for p in payloads]
