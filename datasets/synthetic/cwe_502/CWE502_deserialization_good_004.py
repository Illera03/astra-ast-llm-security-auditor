"""
CWE-502: Insecure Deserialization — Safe
Pattern: json.loads() as a safe alternative to pickle for data exchange.
Reference: NIST Juliet CWE-502 safe variant.
"""

import json


def receive_task(raw_message):
    task = json.loads(raw_message)
    task_type = task.get("type")
    payload = task.get("payload", {})
    if task_type == "compute":
        return run_computation(payload)
    elif task_type == "notify":
        return send_notification(payload)
    return {"error": "unknown task type"}


def run_computation(payload):
    return {"result": payload.get("a", 0) + payload.get("b", 0)}


def send_notification(payload):
    print(f"Notification: {payload.get('message', '')}")
    return {"sent": True}
