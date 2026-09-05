"""Safe: Path(__file__).parent / "data.json" pattern.

Constructing paths relative to the current script's directory is a
common idiom and involves no user-controlled input.
"""

import json
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent


def load_seed_data():
    data_file = BASE_DIR / "data" / "seed.json"
    return json.loads(data_file.read_text(encoding="utf-8"))


def load_migrations():
    migrations_dir = BASE_DIR / "migrations"
    return sorted(migrations_dir.glob("*.sql"))


if __name__ == "__main__":
    seeds = load_seed_data()
    print(f"Loaded {len(seeds)} seed records")
