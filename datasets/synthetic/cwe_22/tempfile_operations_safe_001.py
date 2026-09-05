"""CWE-22 | SAFE | All paths are system-generated via tempfile module.
Uses tempfile.mkdtemp() and tempfile.NamedTemporaryFile() — no user-controlled
path components at any point.
Edge case: file operations are present (open, write, read) but all paths
come from the OS, not from user input. Tests false-positive rate.
"""
import json
import os
import tempfile
from typing import Any


def process_batch(records: list[dict[str, Any]]) -> str:
    work_dir = tempfile.mkdtemp(prefix="batch_")
    results = []
    for _i, record in enumerate(records):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", dir=work_dir, delete=False
        ) as tmp:
            json.dump(record, tmp)
            tmp_path = tmp.name
        with open(tmp_path) as fh:
            parsed = json.load(fh)
            results.append(parsed)
        os.unlink(tmp_path)
    summary_file = tempfile.NamedTemporaryFile(
        mode="w", suffix=".txt", dir=work_dir, delete=False
    )
    summary_file.write(f"Processed {len(results)} records\n")
    summary_path = summary_file.name
    summary_file.close()
    return summary_path
