"""
CWE-78: OS Command Injection — Vulnerable
Pattern: subprocess.run() with % formatting and user input from stdin
Reference: NIST Juliet CWE78_OS_Command_Injection__subprocess_run_01
"""
import subprocess


def compress_file(filename):
    cmd = f"tar -czf archive.tar.gz {filename}"
    subprocess.run(cmd, shell=True, check=True)


def main():
    print("Enter filename to compress:")
    fname = input("> ")
    compress_file(fname)
    print("Done.")


if __name__ == "__main__":
    main()
