"""CWE-22 | VULNERABLE | Flask route using send_file() with user-provided filename.
The user-supplied filename from the URL parameter is joined with the upload
directory and passed directly to send_file(). No send_from_directory() and
no path validation.
Edge case: framework-specific sink (Flask send_file) that AST analysis must
recognize as dangerous.
"""

import os

from flask import Flask, abort, request, send_file

app = Flask(__name__)

UPLOAD_FOLDER = "/var/www/uploads"


@app.route("/download")
def download_file():
    filename = request.args.get("file", "")
    if not filename:
        abort(400, description="Missing file parameter")
    file_path = os.path.join(UPLOAD_FOLDER, filename)
    if not os.path.isfile(file_path):
        abort(404, description="File not found")
    return send_file(file_path, as_attachment=True)


@app.route("/preview")
def preview_file():
    filename = request.args.get("name", "")
    if not filename:
        abort(400)
    path = os.path.join(UPLOAD_FOLDER, filename)
    with open(path) as fh:
        content = fh.read(4096)
    return {"preview": content}
