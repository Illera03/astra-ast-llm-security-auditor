"""
CWE-78: OS Command Injection — Vulnerable
Pattern: subprocess.check_output() with shell=True and user-controlled data from config file
Reference: CVE-2021-29921 (Python ipaddress/net-tools injection patterns)
"""
import json
import subprocess


def check_host_status(config_path):
    with open(config_path) as f:
        config = json.load(f)

    results = {}
    for host in config["hosts"]:
        output = subprocess.check_output(
            "nmap -sP " + host, shell=True
        )
        results[host] = output.decode()
    return results


if __name__ == "__main__":
    report = check_host_status("hosts.json")
    for host, status in report.items():
        print(f"{host}: {status}")
