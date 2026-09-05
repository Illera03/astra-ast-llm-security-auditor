"""CWE-22 | VULNERABLE | open() inside async context manager.
Simulates an aiofiles-style pattern where user-controlled filename is passed
to an async file reader with no path validation.
Edge case: async/await syntax and context managers make the sink harder to trace.
"""
import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager


@asynccontextmanager
async def async_open(path: str, mode: str = "r") -> AsyncIterator:
    fh = open(path, mode)
    try:
        yield fh
    finally:
        fh.close()


async def stream_file_content(user_filename: str) -> str:
    chunks = []
    async with async_open(f"/var/uploads/{user_filename}") as f:
        for line in f:
            chunks.append(line)
            await asyncio.sleep(0)
    return "".join(chunks)


async def handle_download(request_path: str) -> dict:
    try:
        content = await stream_file_content(request_path)
        return {"status": "ok", "data": content}
    except FileNotFoundError:
        return {"status": "error", "data": "not found"}
    except PermissionError:
        return {"status": "error", "data": "forbidden"}
