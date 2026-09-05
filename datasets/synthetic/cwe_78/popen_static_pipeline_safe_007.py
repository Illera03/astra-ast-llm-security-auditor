"""Safe: subprocess.Popen piping two static commands together.

Both commands in the pipeline are hardcoded literals. Bandit flags Popen
and pipe usage, but no user-controlled data is involved. False positive.
"""

import subprocess


def count_error_lines():
    grep_proc = subprocess.Popen(
        ["grep", "ERROR", "/var/log/app/app.log"],
        stdout=subprocess.PIPE,
    )
    wc_proc = subprocess.Popen(
        ["wc", "-l"],
        stdin=grep_proc.stdout,
        stdout=subprocess.PIPE,
        text=True,
    )
    grep_proc.stdout.close()
    output, _ = wc_proc.communicate()
    return int(output.strip())


if __name__ == "__main__":
    count = count_error_lines()
    print(f"Error lines: {count}")
