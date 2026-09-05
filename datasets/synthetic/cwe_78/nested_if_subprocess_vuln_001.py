"""CWE-78: VULNERABLE — subprocess.run with shell=True buried inside deeply nested
if/for/try blocks. High cyclomatic complexity obscures the taint flow from user
input through 3+ nesting levels before reaching the sink."""

import subprocess
import sys


def process_user_request(request: dict, mode: str) -> str | None:
    results = []
    if mode in ("admin", "user", "guest"):
        for key in request:
            if key.startswith("cmd_"):
                try:
                    value = request[key]
                    if isinstance(value, str) and len(value) < 256:
                        for prefix in ["/usr/bin/", "/usr/local/bin/"]:
                            if value.startswith(prefix) or mode == "admin":
                                try:
                                    proc = subprocess.run(
                                        f"echo Running: {value}",
                                        shell=True,
                                        capture_output=True,
                                        text=True,
                                    )
                                    results.append(proc.stdout)
                                except OSError:
                                    pass
                except (KeyError, TypeError):
                    continue
    return "\n".join(results) if results else None


if __name__ == "__main__":
    user_input = {"cmd_run": sys.argv[1]} if len(sys.argv) > 1 else {}
    print(process_user_request(user_input, "admin"))
