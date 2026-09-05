"""CWE-502: shelve.open with user-controlled filename — VULNERABLE.
Edge case: shelve internally uses pickle, but the import is `shelve`
not `pickle`.  Scanners that only look for pickle/yaml/marshal imports
will miss this entirely.
"""
import shelve
from pathlib import Path
from typing import Any


class UserPreferences:
    """Persist per-user preferences using shelve."""

    def __init__(self, storage_dir: str, username: str) -> None:
        safe_name = username.replace("/", "_")
        self._db_path = str(Path(storage_dir) / safe_name)

    def get(self, key: str, default: Any = None) -> Any:
        with shelve.open(self._db_path) as db:  # VULNERABLE: uses pickle
            return db.get(key, default)

    def set(self, key: str, value: Any) -> None:
        with shelve.open(self._db_path) as db:
            db[key] = value

    def delete(self, key: str) -> bool:
        with shelve.open(self._db_path) as db:
            if key in db:
                del db[key]
                return True
            return False


def load_user_prefs(upload_dir: str, user: str) -> dict[str, Any]:
    """Load all preferences for a user (called from web handler)."""
    prefs = UserPreferences(upload_dir, user)
    return {k: prefs.get(k) for k in ("theme", "language", "timezone")}
