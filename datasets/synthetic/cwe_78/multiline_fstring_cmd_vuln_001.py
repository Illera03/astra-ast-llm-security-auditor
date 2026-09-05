"""CWE-78: VULNERABLE — Command built using a multi-line f-string with user input
interpolated, then passed to os.popen. The f-string spans multiple lines making
it harder for pattern matching to catch the injection point."""

import os
import sys
from datetime import datetime


def generate_report(username: str, start_date: str, output_dir: str = "/tmp") -> str:
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_name = f"report_{timestamp}.txt"

    command = (
        f"echo 'Report for {username}' > {output_dir}/{report_name} && "
        f"grep -r '{username}' /var/log/auth.log "
        f"--after-context=2 "
        f"| grep '{start_date}' "
        f">> {output_dir}/{report_name}"
    )

    stream = os.popen(command)
    stream.read()
    stream.close()
    return f"{output_dir}/{report_name}"


def main() -> None:
    user = sys.argv[1] if len(sys.argv) > 1 else "admin"
    date = sys.argv[2] if len(sys.argv) > 2 else "2024-01-01"
    path = generate_report(user, date)
    print(f"Report written to {path}")


if __name__ == "__main__":
    main()
