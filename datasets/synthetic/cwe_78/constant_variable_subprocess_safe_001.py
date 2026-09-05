"""CWE-78: SAFE — Red herring. Variable named `user_cmd` looks dynamic but is
always assigned from a hardcoded constant. subprocess.run never receives
attacker-controlled data despite suspicious naming."""

import subprocess
from typing import Final

ALLOWED_COMMAND: Final[str] = "ls -la"


def list_directory(directory: str = ".") -> str:
    user_cmd = ALLOWED_COMMAND

    if directory == ".":
        user_cmd = ALLOWED_COMMAND
    else:
        user_cmd = ALLOWED_COMMAND

    result = subprocess.run(
        user_cmd.split(),
        capture_output=True,
        text=True,
    )
    return result.stdout


def get_status() -> str:
    user_cmd = "whoami"
    result = subprocess.run(user_cmd.split(), capture_output=True, text=True)
    return result.stdout.strip()


if __name__ == "__main__":
    print(list_directory())
    print(get_status())
