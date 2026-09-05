"""
CWE-78: OS Command Injection — Safe
Pattern: subprocess.check_output() with list arguments
Reference: NIST Juliet CWE78_OS_Command_Injection__check_output_01 (fixed variant)
"""
import subprocess


def search_in_file(pattern, filepath):
    try:
        output = subprocess.check_output(
            ["grep", "-n", pattern, filepath],
            text=True,
        )
        return output.splitlines()
    except subprocess.CalledProcessError:
        return []


def count_lines(filepath):
    output = subprocess.check_output(["wc", "-l", filepath], text=True)
    return int(output.strip().split()[0])


if __name__ == "__main__":
    matches = search_in_file("ERROR", "/var/log/syslog")
    print(f"Found {len(matches)} error lines")
