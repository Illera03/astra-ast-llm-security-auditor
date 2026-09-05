"""Safe: os.system() with a completely hardcoded string.

Bandit always flags os.system, but when the argument is a string literal
with no interpolation, there is no injection vector. False positive.
"""
import os


def clear_temp_files():
    os.system("rm -f /tmp/app_cache_*.tmp")


def restart_service():
    os.system("systemctl restart myapp.service")


if __name__ == "__main__":
    clear_temp_files()
    restart_service()
