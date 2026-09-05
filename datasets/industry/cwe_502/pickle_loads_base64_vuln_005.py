"""CWE-502 Vulnerable: pickle.loads on base64-decoded cookie data.

Deserializing session data from a client cookie allows an attacker
to craft a malicious pickle payload encoded in base64.
"""

import base64
import pickle


def get_session_from_cookie(cookie_value: str) -> dict:
    """Decode and deserialize session data from a client cookie."""
    try:
        raw_bytes = base64.b64decode(cookie_value)
    except Exception:
        return {}

    # VULNERABLE: cookie data is fully attacker-controlled
    session = pickle.loads(raw_bytes)
    return session


def handle_request(cookies: dict) -> dict:
    """Process an incoming HTTP request and restore session."""
    session_cookie = cookies.get("session", "")
    if not session_cookie:
        return {"user": "anonymous"}

    session = get_session_from_cookie(session_cookie)
    return session


if __name__ == "__main__":
    # Simulate a request with a crafted cookie
    fake_cookies = {"session": base64.b64encode(pickle.dumps({"user": "test"})).decode()}
    result = handle_request(fake_cookies)
    print(f"Session: {result}")
