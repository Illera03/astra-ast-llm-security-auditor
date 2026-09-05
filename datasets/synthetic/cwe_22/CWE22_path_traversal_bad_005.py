"""
CWE-22: Path Traversal — Vulnerable
Pattern: shutil.copy with user-controlled source path.
NIST Juliet: CWE22_Improper_Limitation_of_a_Pathname__shutil__01
"""

import os
import shutil

BACKUP_DIR = "/var/backups/"


def backup_user_file(user_src):
    dest = os.path.join(BACKUP_DIR, os.path.basename(user_src))
    shutil.copy(user_src, dest)
    return dest
