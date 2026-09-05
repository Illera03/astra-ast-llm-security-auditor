"""CWE-502: yaml.load without SafeLoader in __init__ — VULNERABLE.
Edge case: the dangerous call is buried inside a class constructor,
making it harder for function-level scanners to flag.  The config file
path comes from user-uploaded content.
"""
import yaml
from pathlib import Path
from typing import Any


class PluginConfig:
    """Loads plugin configuration from a YAML file."""

    name: str
    version: str
    settings: dict[str, Any]

    def __init__(self, config_path: Path) -> None:
        with open(config_path, "r") as fh:
            data = yaml.load(fh)  # VULNERABLE: no Loader argument
        self.name = data.get("name", "unknown")
        self.version = data.get("version", "0.0.0")
        self.settings = data.get("settings", {})

    def __repr__(self) -> str:
        return f"PluginConfig(name={self.name!r}, version={self.version!r})"


def load_user_plugin(upload_dir: str, filename: str) -> PluginConfig:
    """Load a plugin config uploaded by an end-user."""
    path = Path(upload_dir) / filename
    return PluginConfig(path)
