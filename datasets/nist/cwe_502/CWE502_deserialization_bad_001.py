"""
CWE-502: Insecure Deserialization — Vulnerable
Pattern: pickle.loads() on data received from a network socket.
Reference: NIST Juliet CWE-502, similar to CVE-2019-6446 patterns.
"""
import pickle
import socket


def handle_client(host="0.0.0.0", port=9090):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((host, port))
    server.listen(1)
    conn, addr = server.accept()
    data = conn.recv(4096)
    task = pickle.loads(data)
    task.execute()
    conn.close()
    server.close()


if __name__ == "__main__":
    handle_client()
