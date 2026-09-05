"""
CWE-78: OS Command Injection — Safe
Pattern: Using Python stdlib instead of shell commands for file operations
Reference: OWASP recommendation to avoid shell commands when native APIs exist
"""

import os
import shutil
from pathlib import Path


def get_disk_usage(directory):
    total = 0
    for dirpath, _dirnames, filenames in os.walk(directory):
        for f in filenames:
            fp = os.path.join(dirpath, f)
            if os.path.isfile(fp):
                total += os.path.getsize(fp)
    return total


def archive_directory(src, dest):
    shutil.make_archive(dest, "zip", src)


def list_files(directory):
    return list(Path(directory).rglob("*"))


if __name__ == "__main__":
    target = input("Enter directory: ")
    size = get_disk_usage(target)
    print(f"Total size: {size} bytes")
