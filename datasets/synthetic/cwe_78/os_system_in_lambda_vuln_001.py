"""CWE-78: VULNERABLE — os.system called inside a lambda stored in a dict.
The lambda is defined early (line ~15) but invoked much later (line ~35).
Variable-to-sink distance and indirection through a dict challenge taint tracking."""

import os
import sys
from collections.abc import Callable


def build_action_registry() -> dict[str, Callable[[str], int]]:
    registry: dict[str, Callable[[str], int]] = {}

    registry["ping"] = lambda host: os.system(f"ping -c 4 {host}")
    registry["traceroute"] = lambda host: os.system(f"traceroute {host}")
    registry["nslookup"] = lambda host: os.system(f"nslookup {host}")

    registry["help"] = lambda _: print("Available: ping, traceroute, nslookup") or 0

    return registry


def dispatch(action: str, target: str) -> int:
    actions = build_action_registry()
    handler = actions.get(action)
    if handler is None:
        print(f"Unknown action: {action}")
        return 1
    return handler(target)


def main() -> None:
    if len(sys.argv) < 3:
        print("Usage: tool.py <action> <target>")
        sys.exit(1)

    action = sys.argv[1]
    target = sys.argv[2]
    code = dispatch(action, target)
    sys.exit(code)


if __name__ == "__main__":
    main()
