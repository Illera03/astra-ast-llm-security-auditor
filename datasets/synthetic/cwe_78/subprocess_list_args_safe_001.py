"""CWE-78: SAFE — subprocess.run with list arguments and no shell=True. User input
is passed as a separate list element, so the OS treats it as a single argument
rather than a shell-interpreted string. This is the recommended safe pattern."""

import subprocess
import sys
from pathlib import Path
from typing import Optional


def grep_in_file(pattern: str, filepath: Path) -> Optional[str]:
    if not filepath.is_file():
        return None

    result = subprocess.run(
        ["grep", "-n", "--", pattern, str(filepath)],
        capture_output=True,
        text=True,
    )
    return result.stdout if result.returncode == 0 else None


def find_files(directory: Path, name_pattern: str) -> list[str]:
    result = subprocess.run(
        ["find", str(directory), "-name", name_pattern, "-type", "f"],
        capture_output=True,
        text=True,
    )
    return result.stdout.strip().splitlines() if result.stdout else []


def main() -> None:
    pattern = sys.argv[1] if len(sys.argv) > 1 else "TODO"
    search_dir = Path(sys.argv[2]) if len(sys.argv) > 2 else Path(".")

    files = find_files(search_dir, "*.py")
    for f in files:
        matches = grep_in_file(pattern, Path(f))
        if matches:
            print(f"--- {f} ---")
            print(matches)


if __name__ == "__main__":
    main()
