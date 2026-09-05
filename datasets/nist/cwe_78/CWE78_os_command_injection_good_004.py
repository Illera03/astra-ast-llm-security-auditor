"""
CWE-78: OS Command Injection — Safe
Pattern: shlex.quote() used to sanitize user input before shell=True
Reference: Python shlex.quote() mitigation for CWE-78
"""
import shlex
import subprocess


def search_logs(keyword):
    safe_keyword = shlex.quote(keyword)
    cmd = f"grep -r {safe_keyword} /var/log/app/"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return result.stdout


def handle_request(request):
    user_query = request.form.get("query")
    return search_logs(user_query)
