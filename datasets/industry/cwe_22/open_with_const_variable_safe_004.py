"""Safe: file path stored in a module-level constant, then opened.

The path is assigned once at module scope and never modified.
Bandit cannot always determine that the variable is constant.
"""

CONFIG_PATH = "/opt/myservice/settings.ini"
CERT_PATH = "/etc/ssl/certs/myservice.pem"


def read_config():
    with open(CONFIG_PATH, "r") as fh:
        return fh.read()


def read_certificate():
    with open(CERT_PATH, "rb") as fh:
        return fh.read()


if __name__ == "__main__":
    print(read_config()[:80])
