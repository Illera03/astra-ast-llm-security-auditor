"""CWE-22 | SAFE | Config read from hardcoded path only.
Variable is named 'user_config_path' (red herring) but its value is always a
string literal. No user input ever reaches any file open() call.
Edge case: misleading variable names should not cause false positives.
"""
import json
from typing import Any


user_config_path = "/etc/myapp/config.json"
user_data_path = "/etc/myapp/data.json"


def load_config() -> dict[str, Any]:
    with open(user_config_path, "r") as fh:
        return json.load(fh)


def load_data() -> list[dict[str, Any]]:
    with open(user_data_path, "r") as fh:
        return json.load(fh)


def get_setting(key: str, default: Any = None) -> Any:
    config = load_config()
    return config.get(key, default)


def reload_all() -> dict[str, Any]:
    config = load_config()
    data = load_data()
    return {
        "config_keys": list(config.keys()),
        "data_count": len(data),
        "version": config.get("version", "unknown"),
    }
