#!/usr/bin/env python3
"""
Script to clear the ASTra analysis cache.
Useful for testing the same file repeatedly without cache hits.
"""
import os
import sys


def clear_cache(db_path: str = ".astra_cache.db") -> None:
    """Remove the SQLite cache database if it exists."""
    if os.path.exists(db_path):
        try:
            os.remove(db_path)
            print(f"[+] Cache cleared successfully: {db_path}")
        except Exception as e:
            print(f"[!] Error clearing cache: {e}")
            sys.exit(1)
    else:
        print(f"[*] No cache found at: {db_path}")


if __name__ == "__main__":
    clear_cache()
