"""Safe: subprocess.run with static cmd but custom env dict.

Bandit flags subprocess calls that manipulate the environment, but here
both the command and the environment values are hardcoded. False positive.
"""

import os
import subprocess


def run_linter():
    custom_env = os.environ.copy()
    custom_env["PYTHONDONTWRITEBYTECODE"] = "1"
    custom_env["PYTHONPATH"] = "/app/src"

    result = subprocess.run(
        ["python", "-m", "flake8", "src/"],
        env=custom_env,
        capture_output=True,
        text=True,
    )
    return result.returncode, result.stdout


if __name__ == "__main__":
    code, output = run_linter()
    print(output)
    raise SystemExit(code)
