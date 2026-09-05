"""CWE-502: msgpack.unpackb with raw=False — SAFE.
Edge case: msgpack is a binary serialization format, but unlike pickle
it does not support arbitrary object instantiation.  The `raw=False`
flag ensures strings are decoded as str, not bytes.
"""
from typing import Any

import msgpack


def decode_message(data: bytes) -> dict[str, Any]:
    """Decode a msgpack-encoded message from the wire."""
    result = msgpack.unpackb(data, raw=False)  # SAFE: no code execution
    if not isinstance(result, dict):
        raise TypeError(f"Expected dict, got {type(result).__name__}")
    return result


def decode_batch(payloads: list[bytes]) -> list[dict[str, Any]]:
    """Decode a batch of msgpack messages."""
    decoded: list[dict[str, Any]] = []
    for payload in payloads:
        try:
            decoded.append(decode_message(payload))
        except (msgpack.UnpackException, TypeError):
            continue
    return decoded


class MessagePackCodec:
    """Simple codec wrapping msgpack for application use."""

    def encode(self, obj: Any) -> bytes:
        return msgpack.packb(obj, use_bin_type=True)

    def decode(self, data: bytes) -> Any:
        return msgpack.unpackb(data, raw=False)  # SAFE
