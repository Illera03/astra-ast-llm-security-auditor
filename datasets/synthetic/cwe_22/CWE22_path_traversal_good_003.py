"""
CWE-22: Path Traversal — Safe
Pattern: Hardcoded file path with no user-controlled components.
NIST Juliet: CWE22_Improper_Limitation_of_a_Pathname__fixed_path__01
"""

from pathlib import Path


def read_app_license():
    license_path = Path("/usr/share/app/LICENSE.txt")
    return license_path.read_text()


def read_changelog():
    return Path("/usr/share/app/CHANGELOG.md").read_text()
