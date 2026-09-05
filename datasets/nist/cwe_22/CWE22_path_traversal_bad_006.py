"""
CWE-22: Path Traversal — Vulnerable
Pattern: Flask send_file with unvalidated request parameter.
Related: CVE-2021-28363 (pip download path traversal)
"""
from flask import Flask, request, send_file

app = Flask(__name__)


@app.route("/download")
def download():
    path = request.args.get("path", "")
    return send_file(path, as_attachment=True)
