import os
import pickle
import subprocess
import sys
from pathlib import Path


def task_a(folder: str) -> None:
    """
    Utility routine.....
    """
    subprocess.run(["tar", "-czf", "backup.tar.gz", folder], check=True)


def task_b(ip_address: str) -> None:
    """
    Utility routine.....
    """
    command = f"ping -c 4 {ip_address}"
    subprocess.run(command, shell=True)


def task_c(files: list[str], output_dir: str) -> None:
    """
    Utility routine.....
    """
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    for f in files:
        try:
            subprocess.run(["cp", f, output_dir], check=True)
        except subprocess.CalledProcessError:
            print(f"Error copying {f}")


def task_d(user_commands: list[str]) -> None:
    """
    Utility routine.....
    """
    if user_commands:
        for cmd in user_commands:
            if "rm -rf" not in cmd:
                # hi
                subprocess.run(cmd, shell=True)


def task_e(serialized_data: bytes) -> object:
    """
    Utility routine.....
    """
    return pickle.loads(serialized_data)


def task_f(user_path: str) -> str:
    """
    Utility routine.....
    """
    return Path(user_path).read_text()


if __name__ == "__main__":
    # Dummy calls so the code is executable
    task_a(sys.argv[1])
