"""
CWE-78: OS Command Injection — Vulnerable
Pattern: subprocess.run() with shell=True and f-string user input
Reference: CVE-2022-36359 (Django-related command injection patterns)
"""

import subprocess


def search_logs(keyword):
    subprocess.run(f"grep -r '{keyword}' /var/log/", shell=True)


def handle_request(request):
    user_query = request.form.get("query")
    search_logs(user_query)
