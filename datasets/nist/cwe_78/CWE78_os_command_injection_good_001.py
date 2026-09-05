"""
CWE-78: OS Command Injection — Safe
Pattern: subprocess.run() with list arguments, no shell=True
Reference: NIST Juliet CWE78_OS_Command_Injection__subprocess_run_01 (fixed variant)
"""
import subprocess
import sys


def ping_host(host):
    result = subprocess.run(
        ["ping", "-c", "3", host],
        capture_output=True,
        text=True,
    )
    return result.stdout


if __name__ == "__main__":
    target = sys.argv[1]
    output = ping_host(target)
    print(output)
