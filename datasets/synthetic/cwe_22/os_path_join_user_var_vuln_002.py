"""Vulnerable: os.path.join("/base", user_variable) without validation.

os.path.join discards earlier components when a later component is
an absolute path (e.g. "/etc/passwd"), bypassing the intended base.
"""

import os
import sys


def read_user_document(username, doc_name):
    base_dir = "/srv/documents"
    doc_path = os.path.join(base_dir, username, doc_name)
    with open(doc_path) as fh:
        return fh.read()


if __name__ == "__main__":
    user = sys.argv[1]
    name = sys.argv[2]
    print(read_user_document(user, name))
