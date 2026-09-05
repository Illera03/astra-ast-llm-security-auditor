"""Vulnerable: sys.argv passed directly to subprocess.run with shell=True.

Command-line arguments from sys.argv are used directly in a shell command
without any sanitization. Allows arbitrary command injection.
"""
import subprocess
import sys


def compress_file(filepath: str) -> bool:
    result = subprocess.run(
        f"gzip -k {filepath}",
        shell=True,
        capture_output=True,
    )
    return result.returncode == 0


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: script.py <file>")
        sys.exit(1)

    target = sys.argv[1]
    if compress_file(target):
        print(f"Compressed {target}")
    else:
        print("Compression failed")
