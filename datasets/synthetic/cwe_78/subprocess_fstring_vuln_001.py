"""Vulnerable: f-string interpolation of user input in subprocess.run with shell=True.

User input from a web request parameter is embedded directly in a shell
command via f-string. An attacker can inject arbitrary commands.
"""

import subprocess


def search_logs(query: str) -> str:
    result = subprocess.run(
        f"grep -r '{query}' /var/log/app/",
        shell=True,
        capture_output=True,
        text=True,
    )
    return result.stdout


if __name__ == "__main__":
    user_query = input("Search term: ")
    print(search_logs(user_query))
