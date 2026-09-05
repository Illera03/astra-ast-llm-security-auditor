"""
CWE-78: OS Command Injection — Vulnerable
Pattern: os.popen() with user-controlled input from environment variable
Reference: NIST Juliet CWE78_OS_Command_Injection__popen_03
"""

import os


def get_disk_usage(directory):
    stream = os.popen("du -sh " + directory)
    return stream.read()


def report_usage():
    target_dir = os.environ.get("REPORT_DIR", "/tmp")
    usage = get_disk_usage(target_dir)
    print(f"Disk usage: {usage}")


if __name__ == "__main__":
    report_usage()
