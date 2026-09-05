"""CWE-502: pickle.loads inside async function — VULNERABLE.
Edge case: the deserialization happens inside an async coroutine that
reads from a network stream.  Scanners that only analyze synchronous
call graphs may miss async patterns.
"""
import asyncio
import pickle
from typing import Any


async def fetch_remote_object(reader: asyncio.StreamReader) -> Any:
    """Read a length-prefixed pickled object from an async stream."""
    length_bytes = await reader.readexactly(4)
    length = int.from_bytes(length_bytes, "big")
    payload = await reader.readexactly(length)
    return pickle.loads(payload)  # VULNERABLE: untrusted network data


async def handle_client(
    reader: asyncio.StreamReader, writer: asyncio.StreamWriter
) -> None:
    addr = writer.get_extra_info("peername")
    try:
        obj = await fetch_remote_object(reader)
        print(f"[{addr}] received object: {obj!r}")
        writer.write(b"OK\n")
        await writer.drain()
    finally:
        writer.close()
        await writer.wait_closed()


async def main() -> None:
    server = await asyncio.start_server(handle_client, "0.0.0.0", 8888)
    async with server:
        await server.serve_forever()
