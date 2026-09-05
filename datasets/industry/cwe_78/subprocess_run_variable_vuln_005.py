"""Vulnerable: user-supplied variable used as argument in subprocess.run with shell=True.

A package name from user input is passed into a pip install command via
shell=True. An attacker can chain commands through the package name.
"""
import subprocess


def install_package(package_name: str) -> bool:
    result = subprocess.run(
        f"pip install {package_name}",
        shell=True,
        capture_output=True,
        text=True,
    )
    return result.returncode == 0


if __name__ == "__main__":
    pkg = input("Package to install: ")
    if install_package(pkg):
        print(f"Successfully installed {pkg}")
    else:
        print(f"Failed to install {pkg}")
