"""CWE-78: SAFE — Decorator applies shlex.quote to all string arguments before
the wrapped function receives them. Although subprocess.run(shell=True) is used,
every argument is properly escaped. Looks dangerous but is actually safe."""

import functools
import shlex
import subprocess
from typing import Callable, Any


def sanitize_args(func: Callable[..., Any]) -> Callable[..., Any]:
    @functools.wraps(func)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        safe_args = tuple(shlex.quote(a) if isinstance(a, str) else a for a in args)
        safe_kwargs = {
            k: shlex.quote(v) if isinstance(v, str) else v
            for k, v in kwargs.items()
        }
        return func(*safe_args, **safe_kwargs)
    return wrapper


@sanitize_args
def find_files(directory: str, pattern: str) -> str:
    cmd = f"find {directory} -name {pattern} -type f"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return result.stdout


@sanitize_args
def disk_usage(path: str) -> str:
    cmd = f"du -sh {path}"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return result.stdout.strip()


if __name__ == "__main__":
    import sys

    target_dir = sys.argv[1] if len(sys.argv) > 1 else "/tmp"
    print(find_files(target_dir, "*.log"))
    print(disk_usage(target_dir))
