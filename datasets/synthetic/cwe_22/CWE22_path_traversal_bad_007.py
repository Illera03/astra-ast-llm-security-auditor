"""
CWE-22: Path Traversal — Vulnerable
Pattern: Config loader using string concatenation with user-supplied filename.
NIST Juliet: CWE22_Improper_Limitation_of_a_Pathname__open_concat__01
"""

import json

CONFIG_DIR = "/etc/myapp/conf/"


def load_config(user_file):
    with open(CONFIG_DIR + user_file) as f:
        return json.load(f)


def get_setting(user_file, key):
    config = load_config(user_file)
    return config.get(key)
