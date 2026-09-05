"""CWE-502 Vulnerable: yaml.load with explicit yaml.UnsafeLoader.

Using UnsafeLoader explicitly enables deserialization of arbitrary Python
objects from YAML tags like !!python/object/apply, allowing code execution.
"""

import yaml


def load_legacy_config(config_text: str) -> dict:
    """Load a legacy config format that uses custom YAML tags.

    Uses UnsafeLoader to support legacy !!python/object tags in old configs.
    """
    # VULNERABLE: UnsafeLoader allows arbitrary object instantiation
    config = yaml.load(config_text, Loader=yaml.UnsafeLoader)
    return config


def import_external_config(path: str) -> dict:
    """Import configuration from an external YAML file."""
    with open(path) as f:
        content = f.read()
    return load_legacy_config(content)


if __name__ == "__main__":
    sample = """
    app_name: myservice
    debug: true
    workers: 4
    """
    config = load_legacy_config(sample)
    print(f"Config: {config}")
