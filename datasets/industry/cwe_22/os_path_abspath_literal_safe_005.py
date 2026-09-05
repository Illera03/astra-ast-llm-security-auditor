"""Safe: os.path.abspath on a literal string.

Resolving an absolute path from a constant poses no traversal risk.
"""
import os


def get_project_root():
    return os.path.abspath(".")


def get_fixture_dir():
    return os.path.abspath(os.path.join("tests", "fixtures"))


def ensure_output_dir():
    output = os.path.abspath("output")
    os.makedirs(output, exist_ok=True)
    return output


if __name__ == "__main__":
    print("root:", get_project_root())
    print("fixtures:", get_fixture_dir())
