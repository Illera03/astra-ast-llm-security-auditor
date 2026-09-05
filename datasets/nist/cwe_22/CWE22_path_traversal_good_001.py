"""
CWE-22: Path Traversal — Safe
Pattern: os.path.basename strips directory components from user input.
NIST Juliet: CWE22_Improper_Limitation_of_a_Pathname__basename__01
"""
import os
from flask import Flask, request, jsonify

app = Flask(__name__)
BASE_DIR = "/var/www/static"


@app.route("/read")
def read_file():
    filename = request.args.get("file", "")
    safe_name = os.path.basename(filename)
    filepath = os.path.join(BASE_DIR, safe_name)
    with open(filepath, "r") as f:
        return jsonify({"content": f.read()})
