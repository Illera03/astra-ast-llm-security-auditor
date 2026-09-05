"""CWE-502 + CWE-78: pickle.loads AND subprocess shell injection — VULNERABLE.
Edge case: this file contains TWO distinct vulnerabilities in the same
module.  First, untrusted data is deserialized with pickle.loads (CWE-502).
Then a field from the deserialized object is interpolated into a shell
command via subprocess.run with shell=True (CWE-78).
"""

import pickle
import subprocess
from typing import Any


def process_task(raw_payload: bytes) -> str:
    """Deserialize a task payload and execute it."""
    task: dict[str, Any] = pickle.loads(raw_payload)  # VULN: CWE-502

    task_type = task.get("type", "unknown")
    target = task.get("target", "")

    if task_type == "ping":
        cmd = f"ping -c 3 {target}"
        result = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,  # VULN: CWE-78
        )
        return result.stdout
    elif task_type == "dns":
        cmd = f"nslookup {target}"
        result = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,  # VULN: CWE-78
        )
        return result.stdout
    else:
        return f"Unknown task type: {task_type}"


def handle_queue_message(message_body: bytes) -> None:
    """Called by the message queue consumer."""
    output = process_task(message_body)
    print(output)
