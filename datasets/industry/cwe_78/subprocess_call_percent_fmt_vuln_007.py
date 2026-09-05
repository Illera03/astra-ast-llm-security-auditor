"""Vulnerable: % string formatting with untrusted data in subprocess.call.

User-supplied IP address is inserted into a command string using the legacy
% formatting operator. Command injection is possible through the IP input.
"""
import subprocess


def traceroute(ip_address: str) -> int:
    cmd = "traceroute -m 10 %s" % ip_address
    return subprocess.call(cmd, shell=True)


def nslookup(domain: str) -> int:
    cmd = "nslookup %s" % domain
    return subprocess.call(cmd, shell=True)


if __name__ == "__main__":
    target = input("Enter IP or domain: ")
    traceroute(target)
    nslookup(target)
