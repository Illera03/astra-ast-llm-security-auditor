"""CWE-22 | SAFE | pathlib with forced suffix and directory validation.
User input is used to build a Path, but the suffix is forced to '.txt' via
with_suffix() and the resolved path is validated to stay under the allowed
directory. Both constraints together make this safe.
Edge case: user input IS present but constrained by suffix forcing AND
directory containment — tests whether analyzer handles combined mitigations.
"""

from pathlib import Path

NOTES_DIR = Path("/srv/notes").resolve()


def read_note(user_name: str) -> str:
    target = (NOTES_DIR / user_name).with_suffix(".txt").resolve()
    if not str(target).startswith(str(NOTES_DIR)):
        raise PermissionError("Path escapes notes directory")
    if not target.is_file():
        raise FileNotFoundError(f"Note not found: {user_name}")
    return target.read_text(encoding="utf-8")


def write_note(user_name: str, content: str) -> Path:
    target = (NOTES_DIR / user_name).with_suffix(".txt").resolve()
    if not str(target).startswith(str(NOTES_DIR)):
        raise PermissionError("Path escapes notes directory")
    target.write_text(content, encoding="utf-8")
    return target


def list_notes() -> list[str]:
    return [p.stem for p in NOTES_DIR.glob("*.txt") if p.is_file()]
