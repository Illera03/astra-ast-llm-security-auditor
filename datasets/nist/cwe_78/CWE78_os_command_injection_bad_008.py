"""
CWE-78: OS Command Injection — Vulnerable
Pattern: paramiko exec_command() with unsanitized user input
Reference: CVE-2019-14232 (Django/SSH-based management tools)
"""
import paramiko


def run_remote_command(hostname, username, password, command):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(hostname, username=username, password=password)
    stdin, stdout, stderr = client.exec_command("ls -la " + command)
    output = stdout.read().decode()
    client.close()
    return output


def api_handler(request):
    remote_path = request.args.get("path")
    result = run_remote_command("10.0.0.1", "admin", "secret", remote_path)
    return {"output": result}
