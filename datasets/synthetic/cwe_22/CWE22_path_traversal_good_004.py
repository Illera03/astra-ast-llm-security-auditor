"""
CWE-22: Path Traversal — Safe
Pattern: werkzeug.utils.secure_filename sanitizes upload names.
Related: Werkzeug secure_filename mitigation for CVE-2023-37276 patterns
"""

import os

from flask import Flask, request
from werkzeug.utils import secure_filename

app = Flask(__name__)
UPLOAD_DIR = "/var/uploads"


@app.route("/upload", methods=["POST"])
def upload():
    uploaded = request.files["document"]
    safe_name = secure_filename(uploaded.filename)
    dest = os.path.join(UPLOAD_DIR, safe_name)
    uploaded.save(dest)
    return {"status": "ok", "filename": safe_name}
