"""Safe: shutil.copy with two hardcoded paths.

Both source and destination are string literals. No user input
is involved in path construction.
"""
import shutil
import os


def backup_database():
    src = "/var/lib/myapp/production.db"
    dst = "/var/backups/myapp/production.db.bak"
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    shutil.copy2(src, dst)


def install_default_config():
    shutil.copy("defaults/config.yaml", "/etc/myapp/config.yaml")


if __name__ == "__main__":
    backup_database()
    print("Backup complete")
