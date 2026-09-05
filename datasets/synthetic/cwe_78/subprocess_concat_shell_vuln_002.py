"""Vulnerable: string concatenation of user variable in subprocess.call with shell=True.

A filename from user input is concatenated into a shell command string.
An attacker can inject commands via crafted filenames like "; rm -rf /".
"""

import subprocess


def convert_document(filename: str) -> int:
    cmd = "libreoffice --headless --convert-to pdf " + filename
    return subprocess.call(cmd, shell=True)


if __name__ == "__main__":
    user_file = input("File to convert: ")
    exit_code = convert_document(user_file)
    if exit_code != 0:
        print("Conversion failed")
