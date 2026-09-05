"""CWE-22 | SAFE | Chroot-style path jail implementation.
All paths are resolved with os.path.realpath and verified to be within the
jail directory before any file system operation is performed.
Edge case: complex class with multiple file operations, but all go through
the jail check. Tests whether the analyzer can propagate safety through a
shared validation method.
"""
import os
from typing import Optional


class PathJail:
    def __init__(self, jail_root: str):
        self._root = os.path.realpath(jail_root)
        if not os.path.isdir(self._root):
            raise ValueError(f"Jail root does not exist: {jail_root}")

    def _enforce(self, requested: str) -> str:
        candidate = os.path.realpath(os.path.join(self._root, requested))
        if not candidate.startswith(self._root + os.sep):
            if candidate != self._root:
                raise PermissionError("Jail escape attempt blocked")
        return candidate

    def read(self, path: str) -> Optional[str]:
        safe = self._enforce(path)
        if not os.path.isfile(safe):
            return None
        with open(safe, "r") as fh:
            return fh.read()

    def write(self, path: str, data: str) -> None:
        safe = self._enforce(path)
        parent = os.path.dirname(safe)
        os.makedirs(parent, exist_ok=True)
        with open(safe, "w") as fh:
            fh.write(data)

    def delete(self, path: str) -> bool:
        safe = self._enforce(path)
        if os.path.exists(safe):
            os.remove(safe)
            return True
        return False
