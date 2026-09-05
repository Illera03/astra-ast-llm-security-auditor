"""
CWE-502: Insecure Deserialization — Safe
Pattern: yaml.safe_load() for parsing YAML configuration.
Reference: Remediation for CVE-2017-18342 (PyYAML).
"""

import yaml


def load_app_config(config_path):
    with open(config_path) as f:
        config = yaml.safe_load(f)
    return config


def get_database_settings(config_path="/etc/app/config.yml"):
    settings = load_app_config(config_path)
    db = settings.get("database", {})
    return {
        "host": db.get("host", "localhost"),
        "port": db.get("port", 5432),
        "name": db.get("name", "app"),
    }
