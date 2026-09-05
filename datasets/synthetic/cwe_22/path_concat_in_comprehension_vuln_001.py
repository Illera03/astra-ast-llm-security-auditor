"""CWE-22 | VULNERABLE | Path built via concatenation in a comprehension.
User-controlled base_path is concatenated with filenames inside a comprehension,
and each constructed path is opened and read without validation.
Edge case: vulnerability hidden inside a comprehension expression.
"""
import os

ALLOWED_EXTENSIONS = {".txt", ".csv", ".log", ".json"}


def get_extension(name: str) -> str:
    return os.path.splitext(name)[1].lower()


def bulk_read_files(
    base_path: str, filenames: list[str]
) -> list[dict[str, str | None]]:
    paths = [
        base_path + "/" + fname
        for fname in filenames
        if get_extension(fname) in ALLOWED_EXTENSIONS
    ]
    results = []
    for p in paths:
        try:
            with open(p) as fh:
                results.append({"path": p, "content": fh.read(8192)})
        except (FileNotFoundError, PermissionError):
            results.append({"path": p, "content": None})
    return results


def search_in_files(
    base_path: str, filenames: list[str], query: str
) -> list[str]:
    matches = []
    for entry in bulk_read_files(base_path, filenames):
        if entry["content"] and query in entry["content"]:
            matches.append(entry["path"])
    return matches
