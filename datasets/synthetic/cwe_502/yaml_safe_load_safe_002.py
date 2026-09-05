"""CWE-502 Safe: yaml.safe_load() usage.

Pattern: Uses yaml.safe_load() which only constructs basic Python objects.
Bandit may flag the yaml import but safe_load is not vulnerable.
Classification: safe
"""

import yaml


def load_app_config(config_path: str) -> dict:
    with open(config_path) as f:
        raw = f.read()
    config = yaml.safe_load(raw)
    return {
        "host": config.get("host", "localhost"),
        "port": config.get("port", 8080),
        "debug": config.get("debug", False),
    }


if __name__ == "__main__":
    settings = load_app_config("app_config.yml")
    print(settings)
