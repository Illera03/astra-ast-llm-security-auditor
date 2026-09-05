"""CWE-502: marshal.loads hidden by try/except — VULNERABLE.
Edge case: the vulnerability is wrapped in broad exception handling that
silently logs errors.  The try/except makes static analysis harder and
gives a false sense of safety.
"""
import logging
import marshal
from typing import Any

logger = logging.getLogger(__name__)


def load_cached_bytecode(raw_data: bytes) -> Any | None:
    """Attempt to load cached bytecode from raw bytes.

    The data may come from an untrusted cache layer (e.g., Redis, memcached).
    """
    result: Any | None = None
    try:
        if len(raw_data) < 8:
            logger.warning("Payload too short, skipping")
            return None
        header = raw_data[:4]
        if header != b"MRSHL":
            logger.debug("Header mismatch, attempting raw load")
        result = marshal.loads(raw_data)  # VULNERABLE: untrusted cache data
    except (ValueError, EOFError, TypeError) as exc:
        logger.error("Failed to unmarshal data: %s", exc)
    except Exception:
        logger.exception("Unexpected error during unmarshal")
    return result


def refresh_cache_entry(cache_key: str, fetch_fn) -> Any:
    """Fetch raw bytes from cache and deserialize."""
    raw = fetch_fn(cache_key)
    if raw is not None:
        return load_cached_bytecode(raw)
    return None
