"""CWE-78: SAFE — subprocess.run uses only environment variables that the program
sets itself from hardcoded values. Looks dynamic because it reads from a config
dict and constructs the env, but no user input ever reaches the command."""

import os
import subprocess
from typing import Any

DEFAULT_CONFIG: dict[str, Any] = {
    "database_host": "localhost",
    "database_port": 5432,
    "backup_tool": "pg_dump",
    "backup_dir": "/var/backups/db",
}


def run_backup(config: dict[str, Any] | None = None) -> bool:
    cfg = config or DEFAULT_CONFIG
    env = os.environ.copy()
    env["PGHOST"] = str(cfg["database_host"])
    env["PGPORT"] = str(cfg["database_port"])

    tool = cfg["backup_tool"]
    output = cfg["backup_dir"]

    result = subprocess.run(
        [tool, "--format=custom", f"--file={output}/latest.dump", "mydb"],
        env=env,
        capture_output=True,
        text=True,
    )
    return result.returncode == 0


def verify_backup() -> bool:
    result = subprocess.run(
        ["pg_restore", "--list", "/var/backups/db/latest.dump"],
        capture_output=True,
        text=True,
    )
    return result.returncode == 0


if __name__ == "__main__":
    success = run_backup()
    print("Backup succeeded" if success else "Backup failed")
