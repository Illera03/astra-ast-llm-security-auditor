"""CWE-22 | VULNERABLE | Checks for '..' but follows symlinks.
The code validates that the user path does not contain '..' components, but
uses os.path.join (not os.path.realpath) so symlinks within the allowed
directory can point to arbitrary locations outside it.
Edge case: validation is present but insufficient — symlinks bypass the check.
"""
import os

MEDIA_ROOT = "/var/www/media"


def sanitize_path(user_path: str) -> bool:
    components = user_path.replace("\\", "/").split("/")
    for part in components:
        if part == "..":
            return False
        if part.startswith("."):
            return False
    return True


def get_media_file(user_path: str) -> bytes | None:
    if not sanitize_path(user_path):
        raise ValueError("Invalid path characters detected")
    full_path = os.path.join(MEDIA_ROOT, user_path)
    if not os.path.exists(full_path):
        return None
    with open(full_path, "rb") as fh:
        return fh.read()


def get_media_metadata(user_path: str) -> dict:
    if not sanitize_path(user_path):
        return {"error": "invalid path"}
    full_path = os.path.join(MEDIA_ROOT, user_path)
    if not os.path.exists(full_path):
        return {"error": "not found"}
    stat = os.stat(full_path)
    return {
        "size": stat.st_size,
        "is_link": os.path.islink(full_path),
        "path": full_path,
    }
