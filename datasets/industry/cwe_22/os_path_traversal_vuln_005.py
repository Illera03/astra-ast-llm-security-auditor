"""Vulnerable: os.path.join allows ../ traversal from query parameter.

The handler extracts a filename from a simulated HTTP request and
joins it to a base directory without stripping traversal sequences.
"""
import os

UPLOAD_DIR = "/var/www/uploads"


def serve_uploaded_file(request_path):
    filename = request_path.split("/files/")[-1]
    full_path = os.path.join(UPLOAD_DIR, filename)
    with open(full_path, "rb") as fh:
        return fh.read()


if __name__ == "__main__":
    payload = "/files/../../etc/shadow"
    data = serve_uploaded_file(payload)
    print(len(data), "bytes read")
