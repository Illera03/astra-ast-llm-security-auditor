"""
CWE-78: OS Command Injection — Vulnerable
Pattern: subprocess.call() with string concatenation and shell=True
Reference: CVE-2020-7698 (Gerapy remote command execution)
"""
import subprocess


def deploy_project(project_name, branch):
    cmd = (
        "cd /opt/projects/" + project_name
        + " && git checkout " + branch + " && make deploy"
    )
    return subprocess.call(cmd, shell=True)


class DeployView:
    def post(self, request):
        name = request.POST["project"]
        branch = request.POST["branch"]
        result = deploy_project(name, branch)
        return {"status": "ok", "exit_code": result}
