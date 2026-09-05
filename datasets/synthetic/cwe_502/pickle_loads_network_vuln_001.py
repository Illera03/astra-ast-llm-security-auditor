"""CWE-502 Vulnerable: pickle.loads on data received from a network socket.

Deserializing untrusted data from a network connection allows arbitrary
code execution. An attacker can craft a malicious pickle payload.
"""

import pickle
import socket


def receive_task(host: str = "0.0.0.0", port: int = 9999) -> object:
    """Listen for and deserialize a task object from a remote worker."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((host, port))
    server.listen(1)

    conn, addr = server.accept()
    print(f"Connection from {addr}")

    data = b""
    while True:
        chunk = conn.recv(4096)
        if not chunk:
            break
        data += chunk

    conn.close()
    server.close()

    # VULNERABLE: deserializing untrusted network data
    task = pickle.loads(data)
    return task


if __name__ == "__main__":
    task = receive_task()
    print(f"Received task: {task}")
