"""CWE-502 Vulnerable: yaml.load without specifying a Loader parameter.

Using yaml.load() without Loader defaults to yaml.FullLoader in newer
versions, but in older PyYAML versions it uses yaml.Loader which can
execute arbitrary Python objects via YAML tags like !!python/object.
"""

import sys

import yaml


def load_user_config(config_path: str) -> dict:
    """Load user-uploaded YAML configuration file."""
    with open(config_path) as f:
        content = f.read()

    # VULNERABLE: no Loader specified -- unsafe in older PyYAML
    config = yaml.load(content)
    return config


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: script.py <config.yml>")
        sys.exit(1)

    user_config = load_user_config(sys.argv[1])
    print(f"Loaded config with {len(user_config)} keys")
