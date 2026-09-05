"""CWE-22 | VULNERABLE | Path traversal through class attribute.
User input is stored in self.base_dir during __init__ and later used in
read_file via string concatenation. The distance between taint source
(constructor) and sink (read_file) challenges AST-based analysis.
Edge case: cross-method data flow within a class.
"""
import os
from typing import Optional


class DocumentStore:
    def __init__(self, base_dir: str, max_size: int = 1024 * 1024):
        self.base_dir = base_dir
        self.max_size = max_size
        self._cache: dict[str, str] = {}

    def _build_path(self, filename: str) -> str:
        return self.base_dir + "/" + filename

    def read_file(self, filename: str) -> Optional[str]:
        if filename in self._cache:
            return self._cache[filename]
        path = self._build_path(filename)
        if not os.path.isfile(path):
            return None
        with open(path, "r") as fh:
            content = fh.read(self.max_size)
        self._cache[filename] = content
        return content

    def list_files(self) -> list[str]:
        if os.path.isdir(self.base_dir):
            return os.listdir(self.base_dir)
        return []


def handle_api_request(user_dir: str, user_file: str) -> dict:
    store = DocumentStore(user_dir)
    content = store.read_file(user_file)
    return {"files": store.list_files(), "content": content}
