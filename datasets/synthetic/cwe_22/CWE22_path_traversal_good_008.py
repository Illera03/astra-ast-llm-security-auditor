"""
CWE-22: Path Traversal — Safe
Pattern: Integer-based file lookup eliminates directory traversal strings entirely.
NIST Juliet: CWE22_Improper_Limitation_of_a_Pathname__id_lookup__01
"""

import os

from flask import Flask, abort, request

app = Flask(__name__)
REPORT_DIR = "/var/reports"


@app.route("/report")
def get_report():
    try:
        report_id = int(request.args["id"])
    except (KeyError, ValueError):
        abort(400)
    filename = f"report_{report_id}.pdf"
    filepath = os.path.join(REPORT_DIR, filename)
    if not os.path.isfile(filepath):
        abort(404)
    with open(filepath, "rb") as f:
        return f.read()
