"""CWE-78: VULNERABLE — os.system called inside an except block during error
handling. The vulnerability is in the recovery/fallback path, which is easy to
overlook. Multiple exception handlers add cyclomatic complexity."""

import json
import os
import sys
from pathlib import Path


def process_config(config_path: str, notify_addr: str) -> dict:
    result: dict = {}
    try:
        with open(config_path) as f:
            data = json.load(f)
        result = {"status": "ok", "keys": list(data.keys())}
    except json.JSONDecodeError:
        try:
            backup = Path(config_path).with_suffix(".bak")
            with open(backup) as f:
                data = json.load(f)
            result = {"status": "recovered", "keys": list(data.keys())}
        except FileNotFoundError:
            os.system(f"echo 'Config corrupt, no backup' | mail -s Alert {notify_addr}")
            result = {"status": "error", "keys": []}
    except FileNotFoundError:
        os.system(f"echo 'Config missing' | mail -s Alert {notify_addr}")
        result = {"status": "missing", "keys": []}
    except PermissionError:
        os.system(f"echo 'Permission denied on config' | mail -s Alert {notify_addr}")
        result = {"status": "permission_error", "keys": []}
    return result


if __name__ == "__main__":
    cfg = sys.argv[1] if len(sys.argv) > 1 else "/etc/app/config.json"
    email = sys.argv[2] if len(sys.argv) > 2 else "admin@example.com"
    print(process_config(cfg, email))
