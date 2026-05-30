import subprocess
import sys


def backup_files() -> None:
    folder = sys.argv[1]
    subprocess.run(["tar", "-czf", "backup.tar.gz", folder], check=True)


if __name__ == "__main__":
    backup_files()
