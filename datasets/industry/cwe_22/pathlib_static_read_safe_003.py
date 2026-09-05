"""Safe: Path("config.txt").read_text() with a static path.

Pathlib operations on hardcoded filenames carry no traversal risk.
"""
from pathlib import Path


def load_defaults():
    return Path("config.txt").read_text(encoding="utf-8")


def load_schema():
    schema_path = Path("schemas") / "main.json"
    return schema_path.read_text(encoding="utf-8")


if __name__ == "__main__":
    print(load_defaults())
