"""
CWE-22: Path Traversal — Vulnerable
Pattern: os.listdir with user-controlled path exposes directory contents.
Related: CVE-2022-31116 (ujson path traversal via crafted JSON keys)
"""

import os

from flask import Flask, jsonify, request

app = Flask(__name__)


@app.route("/api/list-files")
def list_files():
    user_path = request.args["dir"]
    entries = os.listdir(user_path)
    return jsonify({"files": entries})
