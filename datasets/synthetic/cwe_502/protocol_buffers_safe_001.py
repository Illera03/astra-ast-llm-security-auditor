"""CWE-502: Protocol Buffers deserialization — SAFE.
Edge case: protobuf's ParseFromString looks like deserialization (and it
is), but protocol buffers are type-safe and do not allow arbitrary code
execution.  Scanners should not flag this.
"""
from typing import TypeVar

from google.protobuf.message import Message

T = TypeVar("T", bound=Message)


class SensorReading:
    """Wrapper around a protobuf-generated SensorReading message."""

    def __init__(self, proto_msg: Message) -> None:
        self._msg = proto_msg

    @classmethod
    def from_bytes(cls, data: bytes, msg_class: type[T]) -> "SensorReading":
        """Deserialize from wire format — type-safe, no code execution."""
        msg = msg_class()
        msg.ParseFromString(data)  # SAFE: protobuf, not pickle
        return cls(msg)

    @property
    def temperature(self) -> float:
        return getattr(self._msg, "temperature", 0.0)

    @property
    def humidity(self) -> float:
        return getattr(self._msg, "humidity", 0.0)


def decode_sensor_batch(
    raw_payloads: list[bytes], msg_class: type[T]
) -> list[SensorReading]:
    """Decode a batch of protobuf-encoded sensor readings."""
    return [SensorReading.from_bytes(p, msg_class) for p in raw_payloads]
