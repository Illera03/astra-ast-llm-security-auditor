"""CWE-22 | VULNERABLE | Incomplete path validation.
Only checks for literal '..' but misses URL-encoded variants (%2e%2e),
double-encoded variants (%252e%252e), backslash variants (..\\), and
unicode normalization tricks.
Edge case: presence of a validation function misleads AST analysis into
thinking the path is safe.
"""
import os
from urllib.parse import unquote

UPLOAD_DIR = "/var/www/uploads"


def is_safe_path(user_path: str) -> bool:
    if ".." in user_path:
        return False
    if user_path.startswith("/"):
        return False
    return True


def serve_uploaded_file(raw_filename: str) -> bytes:
    decoded = unquote(raw_filename)
    if not is_safe_path(raw_filename):
        raise ValueError("Invalid path detected")
    full_path = os.path.join(UPLOAD_DIR, decoded)
    with open(full_path, "rb") as fh:
        return fh.read()


def delete_uploaded_file(raw_filename: str) -> bool:
    decoded = unquote(raw_filename)
    if not is_safe_path(raw_filename):
        return False
    full_path = os.path.join(UPLOAD_DIR, decoded)
    if os.path.exists(full_path):
        os.remove(full_path)
        return True
    return False
