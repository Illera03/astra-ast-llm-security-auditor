"""
CWE-78: OS Command Injection — Vulnerable
Pattern: subprocess.Popen() with shell=True and concatenated user input
Reference: NIST Juliet CWE78_OS_Command_Injection__popen_01
"""

import subprocess


def convert_file(input_path, output_format):
    cmd = "ffmpeg -i " + input_path + " -f " + output_format + " output.mp4"
    proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
    return proc.communicate()


if __name__ == "__main__":
    user_file = input("Enter file path: ")
    fmt = input("Enter output format: ")
    convert_file(user_file, fmt)
