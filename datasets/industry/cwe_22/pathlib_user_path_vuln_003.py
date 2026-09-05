"""Vulnerable: Path(request_param).read_text() with user-controlled path.

Simulates a web handler that reads a file based on a query parameter
without any path confinement check.
"""
from pathlib import Path


def handle_request(query_params):
    template_name = query_params.get("template", "default.html")
    template_path = Path("templates") / template_name
    content = template_path.read_text(encoding="utf-8")
    return content


if __name__ == "__main__":
    params = {"template": "../../etc/passwd"}
    print(handle_request(params))
