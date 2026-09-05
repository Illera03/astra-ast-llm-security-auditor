"""CWE-78: VULNERABLE — Command injection through class method chaining. A builder
class accumulates command parts via fluent API calls, and the final execute()
passes the assembled string to os.system."""

import os
from typing import Self


class CommandBuilder:
    def __init__(self) -> None:
        self._parts: list[str] = []
        self._env: dict[str, str] = {}

    def program(self, name: str) -> Self:
        self._parts = [name]
        return self

    def arg(self, value: str) -> Self:
        self._parts.append(value)
        return self

    def env(self, key: str, value: str) -> Self:
        self._env[key] = value
        return self

    def pipe_to(self, program: str) -> Self:
        self._parts.append("|")
        self._parts.append(program)
        return self

    def execute(self) -> int:
        env_prefix = " ".join(f"{k}={v}" for k, v in self._env.items())
        cmd = " ".join(self._parts)
        full_cmd = f"{env_prefix} {cmd}" if env_prefix else cmd
        return os.system(full_cmd)


def search_logs(query: str, log_dir: str = "/var/log") -> int:
    return (
        CommandBuilder()
        .program("grep")
        .arg("-r")
        .arg(query)
        .arg(log_dir)
        .pipe_to("head -20")
        .execute()
    )


if __name__ == "__main__":
    import sys

    search_logs(sys.argv[1] if len(sys.argv) > 1 else "error")
