"""Vulnerable: Path resolution without checking the result stays within allowed dir.

The code resolves a user-supplied path but never verifies that the
resolved path is still under the intended base directory.
"""
from pathlib import Path

ALLOWED_DIR = Path("/srv/shared_files")


def get_shared_file(user_filename):
    target = (ALLOWED_DIR / user_filename).resolve()
    return target.read_bytes()


if __name__ == "__main__":
    content = get_shared_file("../../../etc/passwd")
    print(content[:200])
