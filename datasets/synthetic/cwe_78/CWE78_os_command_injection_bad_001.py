"""
CWE-78: OS Command Injection — Vulnerable
Pattern: os.system() with unsanitized user input from sys.argv
Reference: NIST Juliet CWE78_OS_Command_Injection__os_system_01
"""

import os
import sys


def ping_host(host):
    os.system("ping -c 3 " + host)


if __name__ == "__main__":
    target = sys.argv[1]
    ping_host(target)
