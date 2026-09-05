"""Safe: subprocess.check_output with hardcoded command.

Uses check_output with a static literal command list. No user-controlled
data flows into the command. This is a Bandit false positive.
"""
import subprocess


def get_git_revision():
    output = subprocess.check_output(
        ["git", "rev-parse", "HEAD"],
        text=True,
    )
    return output.strip()


def get_git_branch():
    output = subprocess.check_output(
        ["git", "branch", "--show-current"],
        text=True,
    )
    return output.strip()


if __name__ == "__main__":
    print(f"Branch: {get_git_branch()}")
    print(f"Commit: {get_git_revision()}")
