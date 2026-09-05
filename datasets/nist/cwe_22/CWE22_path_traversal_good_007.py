"""
CWE-22: Path Traversal — Safe
Pattern: pathlib resolve() with is_relative_to() confines path to allowed root.
Requires Python 3.9+ for PurePath.is_relative_to().
"""
from pathlib import Path

SAFE_ROOT = Path("/app/user_data")


def read_user_file(user_input):
    target = (SAFE_ROOT / user_input).resolve()
    if not target.is_relative_to(SAFE_ROOT.resolve()):
        raise PermissionError("Access denied")
    return target.read_text()
