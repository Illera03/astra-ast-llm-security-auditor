"""CWE-22 | SAFE | Correct use of os.path.realpath() after os.path.join().
After joining user input with the base directory, the result is resolved to
its real path and verified to remain under the allowed directory.
Edge case: uses os.path (not pathlib) but is still safe — tests whether
the analyzer understands os-level path resolution.
"""
import os
from typing import Optional


SAFE_ROOT = "/opt/appdata/user_files"


def resolve_and_check(base: str, user_input: str) -> str:
    joined = os.path.join(base, user_input)
    real = os.path.realpath(joined)
    real_base = os.path.realpath(base)
    if not real.startswith(real_base + os.sep) and real != real_base:
        raise PermissionError(f"Path escapes allowed directory: {user_input}")
    return real


def read_file_safely(filename: str) -> Optional[str]:
    try:
        safe_path = resolve_and_check(SAFE_ROOT, filename)
    except PermissionError:
        return None
    if not os.path.isfile(safe_path):
        return None
    with open(safe_path, "r") as fh:
        return fh.read()


def file_info(filename: str) -> dict:
    try:
        safe_path = resolve_and_check(SAFE_ROOT, filename)
    except PermissionError:
        return {"error": "access denied"}
    if not os.path.exists(safe_path):
        return {"error": "not found"}
    stat = os.stat(safe_path)
    return {"size": stat.st_size, "path": safe_path}
