"""Safe: open() with a completely hardcoded file path.

Bandit flags open() calls but this uses only a string literal,
so there is no path traversal risk.
"""

import json


def load_app_config():
    with open("/etc/myapp/config.json") as fh:
        return json.load(fh)


def read_license():
    with open("LICENSE") as fh:
        return fh.read()


if __name__ == "__main__":
    config = load_app_config()
    print(config)
