"""CWE-502: Aliased pickle.loads import — VULNERABLE.
Edge case: `from pickle import loads as deserialize` hides the dangerous
function behind a benign-looking alias. AST scanners that only match
`pickle.loads` by qualified name will miss this.
"""

import socket
from pickle import loads as deserialize
from typing import Any


def receive_object(host: str, port: int) -> Any:
    """Connect to a remote service and deserialize the payload."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, port))
    try:
        chunks: list[bytes] = []
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            chunks.append(chunk)
        raw_payload = b"".join(chunks)
        return deserialize(raw_payload)  # VULNERABLE: aliased pickle.loads
    finally:
        sock.close()


if __name__ == "__main__":
    obj = receive_object("0.0.0.0", 9999)
    print(f"Received: {obj}")
