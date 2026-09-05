"""Safe: subprocess.run with shell=False and static args list.

Explicitly sets shell=False with a hardcoded argument list.
Bandit may still flag the subprocess usage, but this is safe.
"""

import subprocess


def list_running_containers():
    result = subprocess.run(
        ["docker", "ps", "--format", "{{.Names}}"],
        shell=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    return result.stdout.strip().splitlines()


if __name__ == "__main__":
    containers = list_running_containers()
    for name in containers:
        print(name)
