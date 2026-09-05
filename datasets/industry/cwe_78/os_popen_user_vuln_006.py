"""Vulnerable: os.popen() with user-controlled filename.

A filename parameter from external input is interpolated into an os.popen()
call. An attacker can inject shell commands via the filename.
"""
import os


def get_file_type(filename: str) -> str:
    stream = os.popen(f"file {filename}")
    result = stream.read().strip()
    stream.close()
    return result


def get_file_size(filename: str) -> str:
    stream = os.popen("stat -f%z " + filename)
    result = stream.read().strip()
    stream.close()
    return result


if __name__ == "__main__":
    fname = input("Filename: ")
    print(f"Type: {get_file_type(fname)}")
    print(f"Size: {get_file_size(fname)} bytes")
