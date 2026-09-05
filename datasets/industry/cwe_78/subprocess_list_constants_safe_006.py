"""Safe: subprocess.call with list of string constants defined above.

All command components are defined as module-level constants and assembled
into a list. No dynamic data is used. Bandit false positive.
"""
import subprocess

EXECUTABLE = "/usr/bin/rsync"
SOURCE = "/data/uploads/"
DESTINATION = "/backup/uploads/"
FLAGS = "-avz"
EXCLUDE = "--exclude=*.tmp"


def sync_uploads():
    cmd = [EXECUTABLE, FLAGS, EXCLUDE, SOURCE, DESTINATION]
    return subprocess.call(cmd)


if __name__ == "__main__":
    exit_code = sync_uploads()
    if exit_code != 0:
        print(f"Sync failed with code {exit_code}")
