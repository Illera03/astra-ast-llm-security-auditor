"""CWE-502: RestrictedUnpickler — SAFE.
Edge case: pickle is used, but through a custom Unpickler subclass that
overrides find_class to whitelist only known-safe types.  This is the
recommended mitigation from the Python docs.
"""
import io
import pickle
from typing import Any

ALLOWED_CLASSES: dict[str, set[str]] = {
    "builtins": {"dict", "list", "set", "tuple", "int", "float", "str", "bool", "bytes"},
    "collections": {"OrderedDict", "defaultdict"},
    "datetime": {"datetime", "date", "time", "timedelta"},
}


class RestrictedUnpickler(pickle.Unpickler):
    """Only allow deserialization of whitelisted types."""

    def find_class(self, module: str, name: str) -> type:
        allowed = ALLOWED_CLASSES.get(module, set())
        if name in allowed:
            return super().find_class(module, name)
        raise pickle.UnpicklingError(
            f"Disallowed class: {module}.{name}"
        )


def safe_loads(data: bytes) -> Any:
    """Deserialize using the restricted unpickler."""
    return RestrictedUnpickler(io.BytesIO(data)).load()


def safe_round_trip(obj: Any) -> Any:
    raw = pickle.dumps(obj)
    return safe_loads(raw)
