"""Vulnerable: open(f"/data/{user_input}") with f-string path construction.

User-controlled input is interpolated into a path via f-string.
An attacker can supply "../" sequences to escape the /data directory.
"""

import sys


def fetch_report(report_id):
    path = f"/data/reports/{report_id}.csv"
    with open(path) as fh:
        return fh.read()


def download_attachment(attachment_name):
    with open(f"/data/attachments/{attachment_name}", "rb") as fh:
        return fh.read()


if __name__ == "__main__":
    rid = sys.argv[1]
    print(fetch_report(rid))
