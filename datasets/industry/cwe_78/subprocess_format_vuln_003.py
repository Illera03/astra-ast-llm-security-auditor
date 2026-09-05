"""Vulnerable: str.format() with user input passed to subprocess.Popen with shell=True.

User-controlled hostname is inserted into a shell command via str.format().
An attacker can inject commands through the hostname parameter.
"""
import subprocess


def check_host_reachable(hostname: str) -> bool:
    cmd = "ping -c 1 -W 2 {}".format(hostname)
    proc = subprocess.Popen(
        cmd,
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    proc.wait()
    return proc.returncode == 0


if __name__ == "__main__":
    host = input("Hostname to check: ")
    if check_host_reachable(host):
        print("Host is reachable")
    else:
        print("Host is unreachable")
