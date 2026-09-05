"""Vulnerable: os.system() with input() directly embedded.

User input from the terminal is passed straight into os.system() via
f-string interpolation. Full command injection is possible.
"""
import os


def view_file():
    filename = input("Enter filename to view: ")
    os.system(f"cat {filename}")


def disk_usage_for_path():
    path = input("Enter directory path: ")
    os.system(f"du -sh {path}")


if __name__ == "__main__":
    view_file()
    disk_usage_for_path()
