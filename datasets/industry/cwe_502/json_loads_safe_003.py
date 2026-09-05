"""CWE-502 Safe: json.loads() is not vulnerable to deserialization attacks.

Pattern: json.loads() only produces basic Python types (dict, list, str, int,
float, bool, None). Some overly broad rules flag all deserialization but JSON
parsing is inherently safe from code execution.
Classification: safe
"""
import json
import sys


def process_webhook(payload_body: str) -> dict:
    event = json.loads(payload_body)
    event_type = event.get("type", "unknown")
    timestamp = event.get("timestamp")
    data = event.get("data", {})
    return {
        "event_type": event_type,
        "timestamp": timestamp,
        "record_count": len(data.get("records", [])),
    }


if __name__ == "__main__":
    raw = sys.stdin.read()
    result = process_webhook(raw)
    print(json.dumps(result, indent=2))
