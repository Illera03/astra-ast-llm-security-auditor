"""CWE-502: json.loads only — SAFE (red-herring variable names).
Edge case: variable names like `serialized_obj`, `unpickled`, and
`deserialized_payload` look suspicious, but only stdlib json is used.
AST scanners should not flag this file.
"""

import json
from typing import Any


def unpickle_message(raw_bytes: bytes) -> dict[str, Any]:
    """Despite the misleading name, this only uses json.loads."""
    serialized_obj = raw_bytes.decode("utf-8")
    unpickled = json.loads(serialized_obj)
    return unpickled


def process_deserialized_payload(data: bytes) -> list[dict]:
    """Process a batch of JSON-encoded records."""
    deserialized_payload = json.loads(data)
    if not isinstance(deserialized_payload, list):
        deserialized_payload = [deserialized_payload]
    results: list[dict] = []
    for record in deserialized_payload:
        record.setdefault("processed", True)
        results.append(record)
    return results


class PickleJar:
    """Class name is a red herring — no pickle usage whatsoever."""

    def __init__(self, raw_json: str) -> None:
        self.data = json.loads(raw_json)

    def get(self, key: str, default: Any = None) -> Any:
        return self.data.get(key, default)
