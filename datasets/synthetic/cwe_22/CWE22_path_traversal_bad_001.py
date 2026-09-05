"""
CWE-22: Path Traversal — Vulnerable
Pattern: Direct use of user-controlled request parameter in open().
NIST Juliet: CWE22_Improper_Limitation_of_a_Pathname__open__01
"""

from flask import Flask, jsonify, request

app = Flask(__name__)


@app.route("/read")
def read_file():
    filename = request.args["file"]
    with open(filename) as f:
        return jsonify({"content": f.read()})
