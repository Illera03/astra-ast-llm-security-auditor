"""CWE-78: SAFE — Command validated against a strict whitelist before execution.
Although subprocess.run with shell=True is used, only pre-approved commands from
a frozen set can ever be executed. User input selects but cannot modify commands."""

import subprocess
import sys
from typing import Final

ALLOWED_COMMANDS: Final[frozenset[str]] = frozenset(
    {
        "df -h",
        "free -m",
        "uptime",
        "whoami",
        "uname -a",
        "ps aux --sort=-%mem | head -10",
    }
)


def run_system_check(command_name: str) -> str | None:
    normalized = command_name.strip().lower()
    for allowed in ALLOWED_COMMANDS:
        if normalized == allowed:
            result = subprocess.run(allowed, shell=True, capture_output=True, text=True)
            return result.stdout
    return None


def system_dashboard() -> dict[str, str]:
    report: dict[str, str] = {}
    for cmd in sorted(ALLOWED_COMMANDS):
        output = run_system_check(cmd)
        if output:
            report[cmd] = output.strip()
    return report


if __name__ == "__main__":
    if len(sys.argv) > 1:
        out = run_system_check(sys.argv[1])
        print(out if out else f"Command not allowed: {sys.argv[1]}")
    else:
        for name, output in system_dashboard().items():
            print(f"=== {name} ===\n{output}\n")
