"""CWE-502 Safe: Only using pickle.dumps for serialization, not deserialization.

Bandit flags any pickle import, but pickle.dumps is safe since it only
serializes Python objects to bytes -- no code execution risk.
"""

import pickle


def cache_user_session(session_data: dict) -> bytes:
    """Serialize session data for storage in a cache backend."""
    return pickle.dumps(session_data, protocol=pickle.HIGHEST_PROTOCOL)


def cache_result(key: str, value: object) -> tuple:
    """Serialize a computation result for caching."""
    serialized = pickle.dumps(value)
    return (key, serialized)


if __name__ == "__main__":
    data = {"user_id": 42, "role": "admin", "preferences": {"theme": "dark"}}
    blob = cache_user_session(data)
    print(f"Serialized {len(blob)} bytes")
