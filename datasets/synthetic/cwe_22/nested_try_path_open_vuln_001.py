"""CWE-22 | VULNERABLE | Deeply nested try/except/finally around open().
The actual path traversal vulnerability is buried under multiple layers of
error handling. User request parameter flows into open() without validation.
Edge case: high cyclomatic complexity from nested exception handling hides
the vulnerability from simple pattern matching.
"""
import logging
import os

logger = logging.getLogger(__name__)


def fetch_document(request_params: dict) -> str | None:
    filename = request_params.get("document_name", "")
    base = "/var/documents"
    result = None
    try:
        full_path = os.path.join(base, filename)
        try:
            if os.path.getsize(full_path) > 10 * 1024 * 1024:
                logger.warning("File too large: %s", filename)
                return None
            try:
                with open(full_path, encoding="utf-8") as fh:
                    result = fh.read()
            except UnicodeDecodeError:
                try:
                    with open(full_path, encoding="latin-1") as fh:
                        result = fh.read()
                except Exception as inner:
                    logger.error("Inner read failed: %s", inner)
            finally:
                logger.debug("Read attempt finished for %s", filename)
        except OSError as os_err:
            logger.error("OS error: %s", os_err)
        finally:
            logger.debug("Size check block exited")
    except Exception as outer:
        logger.error("Outer error: %s", outer)
    finally:
        logger.info("fetch_document completed for %s", filename)
    return result
