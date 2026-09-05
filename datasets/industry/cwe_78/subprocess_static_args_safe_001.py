"""Safe: subprocess.run with fully hardcoded literal string list args.

Bandit flags subprocess.run calls, but this uses only static literal arguments
with no user input. This is a false positive.
"""
import subprocess


def get_disk_usage():
    result = subprocess.run(
        ["df", "-h", "/"],
        capture_output=True,
        text=True,
    )
    return result.stdout


if __name__ == "__main__":
    print(get_disk_usage())
