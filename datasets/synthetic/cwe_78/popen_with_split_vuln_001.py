"""CWE-78: VULNERABLE — Uses subprocess.Popen with shlex.split on a
user-controlled string. shlex.split only tokenizes — it does NOT sanitize.
An attacker can still inject arguments or exploit the program being called."""

import shlex
import subprocess
import sys


def convert_image(source: str, target: str, extra_opts: str = "") -> bytes | None:
    base = f"convert {source} {extra_opts} {target}"
    tokens = shlex.split(base)

    proc = subprocess.Popen(
        tokens,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    stdout, stderr = proc.communicate()

    if proc.returncode != 0:
        print(f"Error: {stderr.decode()}", file=sys.stderr)
        return None
    return stdout


def batch_convert(files: list[str], output_format: str = "png") -> None:
    for f in files:
        target = f.rsplit(".", 1)[0] + f".{output_format}"
        convert_image(f, target, extra_opts="-quality 85")


if __name__ == "__main__":
    src = sys.argv[1] if len(sys.argv) > 1 else "input.jpg"
    dst = sys.argv[2] if len(sys.argv) > 2 else "output.png"
    opts = sys.argv[3] if len(sys.argv) > 3 else ""
    convert_image(src, dst, opts)
