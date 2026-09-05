"""CWE-502: pickle.loads in dataclass classmethod — VULNERABLE.
Edge case: the vulnerability lives inside a @classmethod factory of a
@dataclass.  This pattern is idiomatic modern Python and may evade
scanners that don't recurse into class bodies.
"""

import pickle
from dataclasses import dataclass, field
from typing import Any, Self


@dataclass
class CacheEntry:
    """A single entry in a distributed cache."""

    key: str
    value: Any
    ttl: int = 300
    tags: list[str] = field(default_factory=list)

    @classmethod
    def from_bytes(cls, key: str, raw: bytes) -> Self:
        """Reconstruct a CacheEntry from its serialized form."""
        payload = pickle.loads(raw)  # VULNERABLE: untrusted bytes
        return cls(
            key=key,
            value=payload.get("value"),
            ttl=payload.get("ttl", 300),
            tags=payload.get("tags", []),
        )

    def to_bytes(self) -> bytes:
        return pickle.dumps(
            {
                "value": self.value,
                "ttl": self.ttl,
                "tags": self.tags,
            }
        )


def get_cache_entry(redis_client, cache_key: str) -> CacheEntry | None:
    raw = redis_client.get(cache_key)
    if raw is None:
        return None
    return CacheEntry.from_bytes(cache_key, raw)
