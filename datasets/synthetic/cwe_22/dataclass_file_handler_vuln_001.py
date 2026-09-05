"""CWE-22 | VULNERABLE | Dataclass with file_path used directly in open().
A dataclass holds a user-supplied file_path field. The read() method uses
this field directly with open() — no validation between construction and use.
Edge case: dataclass pattern with type hints may look structured/safe but
the field value is never sanitized.
"""
from dataclasses import dataclass, field
from typing import Optional
from datetime import datetime


@dataclass
class FileRequest:
    file_path: str
    requester: str
    timestamp: datetime = field(default_factory=datetime.utcnow)
    encoding: str = "utf-8"
    max_bytes: int = 1024 * 1024

    def read(self) -> Optional[str]:
        try:
            with open(self.file_path, "r", encoding=self.encoding) as fh:
                return fh.read(self.max_bytes)
        except (FileNotFoundError, PermissionError):
            return None

    def exists(self) -> bool:
        import os
        return os.path.isfile(self.file_path)

    def size(self) -> int:
        import os
        try:
            return os.path.getsize(self.file_path)
        except OSError:
            return -1


def process_request(path: str, user: str) -> dict:
    req = FileRequest(file_path=path, requester=user)
    content = req.read()
    return {
        "found": content is not None,
        "size": req.size(),
        "requester": req.requester,
        "time": req.timestamp.isoformat(),
    }
