"""
CWE-22: Path Traversal — Safe
Pattern: Allowlist of permitted filenames rejects unlisted requests.
NIST Juliet: CWE22_Improper_Limitation_of_a_Pathname__allowlist__01
"""
from flask import Flask, request, abort, send_from_directory

app = Flask(__name__)

ALLOWED_FILES = {"readme.txt", "license.txt", "changelog.md", "help.html"}
DOCS_DIR = "/var/www/docs"


@app.route("/docs")
def get_doc():
    name = request.args.get("name", "").lower()
    if name not in ALLOWED_FILES:
        abort(403)
    return send_from_directory(DOCS_DIR, name)
