"""
CWE-502: Insecure Deserialization — Vulnerable
Pattern: yaml.load() without specifying a safe Loader.
Reference: CVE-2017-18342 (PyYAML yaml.load unsafe by default).
"""

import yaml


def load_app_config(config_path):
    with open(config_path) as f:
        config_string = f.read()
    config = yaml.load(config_string)
    return config


def apply_settings(config_path="/etc/app/config.yml"):
    settings = load_app_config(config_path)
    db_host = settings.get("database", {}).get("host", "localhost")
    db_port = settings.get("database", {}).get("port", 5432)
    return db_host, db_port


if __name__ == "__main__":
    host, port = apply_settings()
    print(f"Connecting to {host}:{port}")
