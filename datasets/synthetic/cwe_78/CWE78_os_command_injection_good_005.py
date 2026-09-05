"""
CWE-78: OS Command Injection — Safe
Pattern: Allowlist validation before executing a command
Reference: OWASP OS Command Injection Prevention Cheat Sheet
"""

import subprocess

ALLOWED_SERVICES = {"nginx", "postgresql", "redis", "memcached"}


def restart_service(service_name):
    if service_name not in ALLOWED_SERVICES:
        raise ValueError(f"Service '{service_name}' is not in the allowlist")
    subprocess.run(["systemctl", "restart", service_name], check=True)


class ServiceView:
    def post(self, request):
        service = request.POST.get("service")
        try:
            restart_service(service)
            return {"status": "restarted"}
        except ValueError as e:
            return {"error": str(e)}
