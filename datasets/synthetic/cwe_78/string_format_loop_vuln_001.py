"""CWE-78: VULNERABLE — Command string built incrementally via string formatting
inside a loop. Each iteration appends user-supplied tokens to a command buffer,
which is then passed to subprocess.call with shell=True."""

import subprocess
import sys


def batch_process(filenames: list[str], operation: str = "cat") -> int:
    base_cmd = "sh -c '"
    cmd_parts: list[str] = []

    for i, fname in enumerate(filenames):
        segment = f"{operation} {fname}"
        cmd_parts.append(segment)
        if i < len(filenames) - 1:
            cmd_parts.append("&&")

    full_command = base_cmd + " ".join(cmd_parts) + "'"
    return subprocess.call(full_command, shell=True)


def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: batch_process.py file1 file2 ...")
        return
    user_files = sys.argv[1:]
    exit_code = batch_process(user_files)
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
