"""CWE-78: VULNERABLE — Sanitization is present but incomplete. The code strips
semicolons and ampersands but does NOT handle backticks, $() subshell syntax,
pipe characters, or newline injection. Appears secure at first glance."""

import re
import subprocess
import sys


def sanitize_input(user_input: str) -> str:
    cleaned = user_input.replace(";", "")
    cleaned = cleaned.replace("&&", "")
    cleaned = cleaned.replace("||", "")
    cleaned = re.sub(r"[;&]", "", cleaned)
    return cleaned.strip()


def lookup_dns(hostname: str) -> str:
    safe_host = sanitize_input(hostname)
    cmd = f"dig +short {safe_host}"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return result.stdout.strip()


def check_port(host: str, port: str) -> bool:
    safe_host = sanitize_input(host)
    safe_port = sanitize_input(port)
    cmd = f"nc -z -w 2 {safe_host} {safe_port}"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return result.returncode == 0


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    print(f"DNS: {lookup_dns(target)}")
    print(f"Port 80 open: {check_port(target, '80')}")
