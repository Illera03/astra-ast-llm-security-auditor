"""CWE-502: yaml.safe_load — SAFE.
Edge case: YAML is used, but exclusively via yaml.safe_load(), which
does not allow arbitrary Python object instantiation.  A naïve scanner
that flags any `yaml.load*` call would produce a false positive.
"""
import yaml
from pathlib import Path
from typing import Any


def load_app_config(config_path: Path) -> dict[str, Any]:
    """Load application configuration from a YAML file."""
    with open(config_path, "r") as fh:
        config = yaml.safe_load(fh)
    if config is None:
        return {}
    return config


def merge_configs(*paths: Path) -> dict[str, Any]:
    """Merge multiple YAML config files, last wins."""
    merged: dict[str, Any] = {}
    for path in paths:
        if path.exists():
            partial = load_app_config(path)
            merged.update(partial)
    return merged


class YAMLConfigProvider:
    """Provides configuration values from a YAML source."""

    def __init__(self, raw_yaml: str) -> None:
        self._data: dict[str, Any] = yaml.safe_load(raw_yaml) or {}

    def get(self, key: str, default: Any = None) -> Any:
        return self._data.get(key, default)

    def keys(self) -> list[str]:
        return list(self._data.keys())
