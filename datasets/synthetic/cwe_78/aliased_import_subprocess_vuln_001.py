"""CWE-78: VULNERABLE — Aliased imports: `from subprocess import run as execute`
and `from subprocess import call as invoke`. AST analyzers that only match
against 'subprocess.run' or 'subprocess.call' will miss these sinks."""

from subprocess import run as execute
from subprocess import call as invoke
import sys
from typing import Optional


def deploy_service(service_name: str, version: str) -> Optional[str]:
    cmd = f"docker pull registry.internal/{service_name}:{version}"
    result = execute(cmd, shell=True, capture_output=True, text=True)
    if result.returncode == 0:
        return result.stdout.strip()
    return None


def restart_service(service_name: str) -> int:
    return invoke(
        f"systemctl restart {service_name}",
        shell=True,
    )


def rollback(service_name: str, previous_version: str) -> bool:
    pull_result = deploy_service(service_name, previous_version)
    if pull_result:
        code = restart_service(service_name)
        return code == 0
    return False


if __name__ == "__main__":
    svc = sys.argv[1] if len(sys.argv) > 1 else "web"
    ver = sys.argv[2] if len(sys.argv) > 2 else "latest"
    print(deploy_service(svc, ver))
