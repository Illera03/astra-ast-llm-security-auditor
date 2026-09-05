"""
CWE-22: Path Traversal — Vulnerable
Pattern: pathlib.Path constructed from user-controlled directory variable.
NIST Juliet: CWE22_Improper_Limitation_of_a_Pathname__pathlib__01
"""
import sys
from pathlib import Path


def load_user_document(user_dir):
    doc_path = Path(user_dir) / "report.txt"
    return doc_path.read_text()


if __name__ == "__main__":
    directory = sys.argv[1]
    print(load_user_document(directory))
