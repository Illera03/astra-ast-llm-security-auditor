"""Safe: os.path.join with only string literal arguments.

Static analyzers may flag os.path.join as a potential path traversal
vector, but all arguments here are constants.
"""

import os


def get_data_path():
    return os.path.join("/var", "lib", "myapp", "data.db")


def get_log_path():
    return os.path.join("/var", "log", "myapp", "access.log")


if __name__ == "__main__":
    print(get_data_path())
    print(get_log_path())
