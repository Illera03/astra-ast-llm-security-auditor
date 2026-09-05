"""
CWE-78: OS Command Injection — Safe
Pattern: Parameterized command with regex validation on user input
Reference: CWE-78 mitigation via input validation
"""

import re
import subprocess

HOSTNAME_RE = re.compile(r"^[a-zA-Z0-9._-]+$")


def check_dns(hostname):
    if not HOSTNAME_RE.match(hostname):
        raise ValueError("Invalid hostname format")
    result = subprocess.run(
        ["dig", "+short", hostname],
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


if __name__ == "__main__":
    host = input("Enter hostname: ")
    try:
        ip = check_dns(host)
        print(f"Resolved: {ip}")
    except ValueError as e:
        print(f"Error: {e}")
