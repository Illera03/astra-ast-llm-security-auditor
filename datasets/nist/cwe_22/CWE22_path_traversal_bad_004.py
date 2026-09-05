"""
CWE-22: Path Traversal — Vulnerable
Pattern: String concatenation to build file path from user input in upload handler.
Related: CVE-2020-28493 (Jinja2 sandbox escape via path traversal)
"""
import os


UPLOAD_DIR = "/uploads/"


def save_upload(filename, data):
    target = UPLOAD_DIR + filename
    with open(target, "wb") as f:
        f.write(data)
    return target


def download_upload(filename):
    path = "/uploads/" + filename
    with open(path, "rb") as f:
        return f.read()
