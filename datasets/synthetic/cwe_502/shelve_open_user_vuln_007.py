"""CWE-502 Vulnerable: shelve.open with a user-provided file path.

shelve uses pickle internally. Opening a user-controlled shelve database
means deserializing attacker-controlled pickle data, enabling arbitrary
code execution.
"""

import shelve
import sys


def load_user_database(db_path: str) -> dict:
    """Load all entries from a user-specified shelve database."""
    results = {}

    # VULNERABLE: user controls which shelve db gets opened/deserialized
    with shelve.open(db_path) as db:
        for key in db:
            results[key] = db[key]

    return results


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: script.py <database_path>")
        sys.exit(1)

    db_path = sys.argv[1]
    entries = load_user_database(db_path)
    print(f"Loaded {len(entries)} entries from {db_path}")
    for key, value in entries.items():
        print(f"  {key}: {value}")
