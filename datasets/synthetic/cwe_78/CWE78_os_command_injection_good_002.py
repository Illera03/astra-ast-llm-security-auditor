"""
CWE-78: OS Command Injection — Safe
Pattern: os.system() with hardcoded command, no user input
Reference: NIST Juliet CWE78_OS_Command_Injection__os_system_01 (fixed variant)
"""

import os


def rotate_logs():
    os.system("logrotate /etc/logrotate.d/myapp")


def show_date():
    os.system("date")


def flush_dns():
    os.system("systemd-resolve --flush-caches")


if __name__ == "__main__":
    show_date()
    rotate_logs()
