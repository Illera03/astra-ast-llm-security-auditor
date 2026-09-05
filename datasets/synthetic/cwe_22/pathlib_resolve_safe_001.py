"""CWE-22 | SAFE | Proper path containment using pathlib.Path.resolve().
Resolves the user-supplied path and checks that the resolved absolute path
starts with the allowed base directory. This correctly prevents traversal
even with symlinks and encoded components.
Edge case: user input IS present, but the validation is correct — tests
whether the analyzer can recognize effective sanitization.
"""

from pathlib import Path

ALLOWED_BASE = Path("/srv/user_files").resolve()


class SecureFileReader:
    def __init__(self, base: Path = ALLOWED_BASE):
        self.base = base.resolve()

    def _validate_path(self, requested: str) -> Path:
        target = (self.base / requested).resolve()
        if not str(target).startswith(str(self.base)):
            raise PermissionError(
                f"Access denied: {requested} resolves outside allowed directory"
            )
        return target

    def read(self, requested: str) -> str | None:
        safe_path = self._validate_path(requested)
        if not safe_path.is_file():
            return None
        return safe_path.read_text(encoding="utf-8")

    def exists(self, requested: str) -> bool:
        try:
            safe_path = self._validate_path(requested)
            return safe_path.exists()
        except PermissionError:
            return False
