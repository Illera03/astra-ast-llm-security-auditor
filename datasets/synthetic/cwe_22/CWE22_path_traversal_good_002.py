"""
CWE-22: Path Traversal — Safe
Pattern: os.path.realpath + startswith check to confine access to base directory.
NIST Juliet: CWE22_Improper_Limitation_of_a_Pathname__realpath__01
"""

import os

BASE_DIR = "/var/www/data"


def safe_read(user_filename):
    requested = os.path.realpath(os.path.join(BASE_DIR, user_filename))
    if not requested.startswith(os.path.realpath(BASE_DIR) + os.sep):
        raise PermissionError("Access denied: path traversal detected")
    with open(requested) as f:
        return f.read()
