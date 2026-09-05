"""
CWE-78: OS Command Injection — Safe
Pattern: subprocess.Popen() with list arguments, no shell involvement
Reference: NIST Juliet CWE78_OS_Command_Injection__popen_01 (fixed variant)
"""
import subprocess


def convert_image(input_path, output_path, width, height):
    proc = subprocess.Popen(
        ["convert", input_path, "-resize", f"{width}x{height}", output_path],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    stdout, stderr = proc.communicate()
    if proc.returncode != 0:
        raise RuntimeError(f"Conversion failed: {stderr.decode()}")
    return stdout.decode()


if __name__ == "__main__":
    convert_image("photo.png", "thumb.png", 128, 128)
