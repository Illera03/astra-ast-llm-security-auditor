"""
CWE-502: Insecure Deserialization — Safe
Pattern: numpy.load() with allow_pickle=False for untrusted files.
Reference: Remediation for CVE-2019-6446 (numpy.load).
"""
import os
import tempfile

import numpy as np


def process_uploaded_array(file_storage):
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".npy")
    file_storage.save(tmp.name)
    tmp.close()
    data = np.load(tmp.name, allow_pickle=False)
    os.unlink(tmp.name)
    return {"mean": float(data.mean()), "shape": list(data.shape)}


def upload_handler(request):
    uploaded = request.files["data"]
    return process_uploaded_array(uploaded)
