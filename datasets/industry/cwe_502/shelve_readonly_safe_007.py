"""CWE-502 Safe: shelve.open with flag='r' on a known static database file.

While shelve uses pickle internally, opening a known local file in read-only
mode with a hardcoded path is equivalent to reading a trusted config file.
"""

import shelve

CONFIG_DB = "/etc/myapp/defaults.db"


def load_defaults() -> dict:
    """Load application defaults from a known, read-only shelve database."""
    defaults = {}
    with shelve.open(CONFIG_DB, flag="r") as db:
        for key in db:
            defaults[key] = db[key]
    return defaults


if __name__ == "__main__":
    try:
        settings = load_defaults()
        print(f"Loaded {len(settings)} default settings")
    except FileNotFoundError:
        print("Defaults database not found, using built-in defaults")
