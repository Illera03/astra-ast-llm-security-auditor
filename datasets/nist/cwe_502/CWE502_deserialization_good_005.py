"""
CWE-502: Insecure Deserialization — Safe
Pattern: HMAC verification before deserializing pickled cache data.
Reference: Django signed cookie pattern, NIST Juliet CWE-502 safe variant.
"""
import hashlib
import hmac
import pickle

SECRET_KEY = b"app-secret-key-from-env"


def sign_data(data):
    raw = pickle.dumps(data)
    sig = hmac.new(SECRET_KEY, raw, hashlib.sha256).hexdigest()
    return sig, raw


def load_signed_cache(signature, raw_bytes):
    expected = hmac.new(SECRET_KEY, raw_bytes, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(signature, expected):
        raise ValueError("Cache integrity check failed")
    return pickle.loads(raw_bytes)
