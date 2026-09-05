"""CWE-22 | SAFE | open() aliased as file_reader but only used with hardcoded paths.
The builtin open is aliased to file_reader. Despite the alias and a function
parameter named 'filename', no user input ever reaches a file operation.
Edge case: aliased builtins + misleading parameter names should not trigger
false positives.
"""
import json
from typing import Any

file_reader = open

DEFAULT_SETTINGS = "/etc/myapp/defaults.json"
OVERRIDE_SETTINGS = "/etc/myapp/overrides.json"


def load_defaults() -> dict[str, Any]:
    with file_reader(DEFAULT_SETTINGS, "r") as fh:
        return json.load(fh)


def load_overrides() -> dict[str, Any]:
    with file_reader(OVERRIDE_SETTINGS, "r") as fh:
        return json.load(fh)


def merge_settings() -> dict[str, Any]:
    defaults = load_defaults()
    overrides = load_overrides()
    defaults.update(overrides)
    return defaults


def display_setting(filename: str) -> str:
    """Accepts a filename parameter but only uses it as a dictionary key."""
    settings = merge_settings()
    value = settings.get(filename, "not found")
    return f"Setting '{filename}' = {value}"


def all_keys() -> list[str]:
    return sorted(merge_settings().keys())
