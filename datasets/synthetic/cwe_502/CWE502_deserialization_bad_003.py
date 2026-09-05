"""
CWE-502: Insecure Deserialization — Vulnerable
Pattern: marshal.loads() on user-uploaded data in a web handler.
Reference: NIST Juliet CWE-502.
"""

import base64
import marshal


def execute_uploaded_code(request_body):
    encoded_data = request_body.get("bytecode")
    raw = base64.b64decode(encoded_data)
    code_object = marshal.loads(raw)
    result = exec(code_object)
    return {"status": "ok", "result": result}


def api_handler(environ):
    import json

    body = environ["wsgi.input"].read()
    payload = json.loads(body)
    return execute_uploaded_code(payload)
