"""Vulnerable: shutil.move with user-controlled destination path.

The destination directory comes from user input, allowing an attacker
to move files to arbitrary locations on the filesystem.
"""
import shutil
import sys
import os


def relocate_export(export_id, destination_dir):
    src = os.path.join("/tmp/exports", f"{export_id}.tar.gz")
    dst = os.path.join(destination_dir, f"{export_id}.tar.gz")
    shutil.move(src, dst)
    return dst


if __name__ == "__main__":
    eid = sys.argv[1]
    dest = sys.argv[2]
    result = relocate_export(eid, dest)
    print(f"Moved to {result}")
