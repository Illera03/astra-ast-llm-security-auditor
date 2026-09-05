"""
CWE-502: Insecure Deserialization — Vulnerable
Pattern: jsonpickle.decode() on untrusted API input.
Reference: NIST Juliet CWE-502, jsonpickle enables arbitrary object instantiation.
"""

import json

import jsonpickle


def process_webhook(raw_body):
    payload = json.loads(raw_body)
    event_data = payload.get("event")
    event_obj = jsonpickle.decode(json.dumps(event_data))
    event_obj.handle()
    return {"processed": True}


def webhook_endpoint(environ):
    body = environ["wsgi.input"].read().decode("utf-8")
    return process_webhook(body)
