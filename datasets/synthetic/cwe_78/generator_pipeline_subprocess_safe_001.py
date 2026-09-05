"""CWE-78: SAFE — Generators and itertools process user data, but subprocess.run
is only called with fully hardcoded commands. User data flows into file contents
written via Python's open(), never into command arguments."""

import subprocess
import itertools
import tempfile
from pathlib import Path
from typing import Generator


def normalize_records(raw: list[str]) -> Generator[str, None, None]:
    for record in raw:
        stripped = record.strip()
        if stripped and not stripped.startswith("#"):
            yield stripped.lower()


def chunk_records(records: Generator[str, None, None], size: int = 100) -> Generator[list[str], None, None]:
    iterator = iter(records)
    while True:
        chunk = list(itertools.islice(iterator, size))
        if not chunk:
            break
        yield chunk


def process_and_sort(user_data: list[str], output_path: Path) -> bool:
    normalized = normalize_records(user_data)
    with open(output_path, "w") as f:
        for chunk in chunk_records(normalized):
            for line in chunk:
                f.write(line + "\n")

    result = subprocess.run(
        ["sort", "-u", "-o", str(output_path), str(output_path)],
        capture_output=True,
        text=True,
    )
    return result.returncode == 0


if __name__ == "__main__":
    sample_data = ["Banana", "apple", "  Cherry ", "# comment", "apple", "DATE"]
    out = Path(tempfile.mktemp(suffix=".txt"))
    if process_and_sort(sample_data, out):
        print(out.read_text())
    out.unlink(missing_ok=True)
