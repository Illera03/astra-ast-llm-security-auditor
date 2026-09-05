"""Vulnerable: os.environ value used unsanitized in subprocess.run with shell=True.

An environment variable controlled by the deployment context or user is read
and embedded into a shell command. If the environment is attacker-controlled
(e.g., in a CI pipeline or container), this enables command injection.
"""

import os
import subprocess


def deploy_to_target():
    deploy_host = os.environ.get("DEPLOY_HOST", "localhost")
    deploy_path = os.environ.get("DEPLOY_PATH", "/opt/app")

    subprocess.run(
        f"rsync -avz ./dist/ {deploy_host}:{deploy_path}",
        shell=True,
        check=True,
    )


def notify_channel():
    webhook_url = os.environ.get("SLACK_WEBHOOK", "")
    message = os.environ.get("DEPLOY_MESSAGE", "Deployed successfully")
    subprocess.run(
        f'curl -X POST -d \'{{"text": "{message}"}}\' {webhook_url}',
        shell=True,
    )


if __name__ == "__main__":
    deploy_to_target()
    notify_channel()
