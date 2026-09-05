"""CWE-22 | VULNERABLE | pathlib.Path with dynamic user arg inside a decorator.
The decorator wraps file operations with logging but does not sanitize the
path argument. User-controlled input flows directly into Path().
Edge case: decorator indirection hides the dangerous sink from simple AST walks.
"""
import logging
from pathlib import Path
from functools import wraps
from typing import Callable, Any

logger = logging.getLogger(__name__)


def log_file_access(func: Callable) -> Callable:
    @wraps(func)
    def wrapper(filepath: str, *args: Any, **kwargs: Any) -> Any:
        logger.info("Accessing file: %s", filepath)
        result = func(filepath, *args, **kwargs)
        logger.info("Finished accessing: %s", filepath)
        return result
    return wrapper


@log_file_access
def read_user_document(filepath: str) -> str:
    target = Path("/srv/documents") / filepath
    return target.read_text(encoding="utf-8")


@log_file_access
def get_file_size(filepath: str) -> int:
    target = Path("/srv/documents") / filepath
    return target.stat().st_size


def handle_request(user_input: str) -> dict:
    content = read_user_document(user_input)
    size = get_file_size(user_input)
    return {"content": content, "size": size}
