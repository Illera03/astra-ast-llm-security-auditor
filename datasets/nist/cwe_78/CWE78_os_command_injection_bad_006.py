"""
CWE-78: OS Command Injection — Vulnerable
Pattern: os.system() with format string from network input (socket)
Reference: NIST Juliet CWE78_OS_Command_Injection__socket_01
"""
import os
import socket


def handle_client(conn):
    data = conn.recv(1024).decode("utf-8").strip()
    os.system(f"echo {data} >> /var/log/client_messages.log")
    conn.sendall(b"Message logged.\n")


def start_server():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("0.0.0.0", 9999))
    srv.listen(5)
    while True:
        conn, addr = srv.accept()
        handle_client(conn)
        conn.close()


if __name__ == "__main__":
    start_server()
