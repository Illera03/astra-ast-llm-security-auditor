"""
CWE-22: Path Traversal — Safe
Pattern: os.path.abspath check ensures resolved path stays within base directory.
NIST Juliet: CWE22_Improper_Limitation_of_a_Pathname__abspath__01
"""

import os

BASE_DIR = "/srv/app/data"


def safe_file_access(user_input):
    candidate = os.path.abspath(os.path.join(BASE_DIR, user_input))
    base = os.path.abspath(BASE_DIR)
    if not candidate.startswith(base + os.sep):
        raise ValueError("Invalid path")
    with open(candidate) as f:
        return f.read()
