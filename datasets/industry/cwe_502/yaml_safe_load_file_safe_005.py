"""CWE-502 Safe: yaml.safe_load() reading from a static config file.

Pattern: Opens a hardcoded config file path and uses yaml.safe_load().
Both the file path and the loader are safe. Bandit may flag the yaml
import or the open() call.
Classification: safe
"""
import yaml


def load_database_config() -> dict:
    with open("config/database.yml") as fh:
        db_config = yaml.safe_load(fh)

    env = db_config.get("production", {})
    return {
        "engine": env.get("adapter", "postgresql"),
        "host": env.get("host", "127.0.0.1"),
        "port": env.get("port", 5432),
        "name": env.get("database", "app_production"),
        "pool_size": env.get("pool", 5),
    }


if __name__ == "__main__":
    config = load_database_config()
    print(config)
