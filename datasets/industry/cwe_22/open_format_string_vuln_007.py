"""Vulnerable: open("/uploads/{}".format(filename)) with unsanitized filename.

User-controlled filename is inserted via str.format() without any
sanitization or traversal check before being passed to open().
"""


def read_upload(filename):
    path = "/uploads/{}".format(filename)
    with open(path, "r") as fh:
        return fh.read()


def read_avatar(username, avatar_file):
    path = "/uploads/avatars/{}/{}".format(username, avatar_file)
    with open(path, "rb") as fh:
        return fh.read()


if __name__ == "__main__":
    content = read_upload("../../../etc/passwd")
    print(content)
