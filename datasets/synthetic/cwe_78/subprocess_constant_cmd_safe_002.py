"""Safe: subprocess.Popen with a constant command defined at module level.

The command is a module-level constant with no dynamic components.
Bandit flags Popen usage but this is a false positive.
"""

import subprocess

BACKUP_CMD = ["tar", "czf", "/tmp/backup.tar.gz", "/var/log/app"]


def run_backup():
    proc = subprocess.Popen(
        BACKUP_CMD,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    stdout, stderr = proc.communicate()
    if proc.returncode != 0:
        raise RuntimeError(f"Backup failed: {stderr.decode()}")
    return stdout.decode()


if __name__ == "__main__":
    print(run_backup())
