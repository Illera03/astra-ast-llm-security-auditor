"""Vulnerable: open(input()) directly with user-supplied filename.

User input flows directly into open() with no path validation,
allowing arbitrary file reads via traversal (e.g. ../../../etc/passwd).
"""


def view_file():
    filename = input("Enter filename to view: ")
    with open(filename) as fh:
        print(fh.read())


if __name__ == "__main__":
    view_file()
