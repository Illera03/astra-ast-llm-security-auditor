"""
CWE-22: Path Traversal — Vulnerable
Pattern: os.path.join with unsanitized user input allows absolute path override.
Related: CVE-2023-37276 (aiohttp static file serving path traversal)
"""
import os

BASE_DIR = "/var/www/static"


def serve_static(user_filename):
    filepath = os.path.join(BASE_DIR, user_filename)
    with open(filepath, "rb") as f:
        return f.read()
