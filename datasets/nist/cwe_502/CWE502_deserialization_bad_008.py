"""
CWE-502: Insecure Deserialization — Vulnerable
Pattern: numpy.load() with allow_pickle=True on untrusted file upload.
Reference: CVE-2019-6446 (numpy.load allow_pickle default was True).
"""
import numpy as np
import tempfile
import os


def process_uploaded_array(file_storage):
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".npy")
    file_storage.save(tmp.name)
    tmp.close()
    data = np.load(tmp.name, allow_pickle=True)
    os.unlink(tmp.name)
    return {"mean": float(data.mean()), "shape": list(data.shape)}


def upload_handler(request):
    uploaded = request.files["data"]
    return process_uploaded_array(uploaded)
