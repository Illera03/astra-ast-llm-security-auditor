"""CWE-502 Vulnerable: pickle.loads on data retrieved from an external cache.

Even though Redis is infrastructure, cache data can be poisoned by an
attacker who gains write access to the cache. Deserializing cached
values with pickle enables remote code execution.
"""

import pickle
import socket


class SimpleRedisClient:
    """Minimal Redis-like client for demonstration purposes."""

    def __init__(self, host: str = "localhost", port: int = 6379):
        self.host = host
        self.port = port

    def get(self, key: str) -> bytes:
        """Retrieve raw bytes for a key from the cache server."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((self.host, self.port))
        sock.sendall(f"GET {key}\r\n".encode())
        data = sock.recv(65536)
        sock.close()
        return data


def get_cached_object(cache: SimpleRedisClient, key: str) -> object:
    """Retrieve and deserialize a cached Python object."""
    raw_data = cache.get(key)
    if raw_data is None:
        return None

    # VULNERABLE: cache data could be poisoned by an attacker
    return pickle.loads(raw_data)


if __name__ == "__main__":
    cache = SimpleRedisClient()
    result = get_cached_object(cache, "user:session:abc123")
    print(f"Cached object: {result}")
