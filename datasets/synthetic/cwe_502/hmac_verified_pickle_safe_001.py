"""CWE-502: HMAC-verified pickle.loads — SAFE.
Edge case: pickle.loads is present, but the data is HMAC-verified with
a server-side secret before deserialization.  This prevents tampering
and makes exploitation infeasible without the secret key.
"""
import hmac
import hashlib
import pickle
from typing import Any

SECRET_KEY = b"server-side-secret-loaded-from-vault"
DIGEST_SIZE = hashlib.sha256().digest_size


def sign_payload(obj: Any) -> bytes:
    """Serialize and sign an object."""
    raw = pickle.dumps(obj, protocol=pickle.HIGHEST_PROTOCOL)
    signature = hmac.new(SECRET_KEY, raw, hashlib.sha256).digest()
    return signature + raw


def verify_and_load(signed_data: bytes) -> Any:
    """Verify HMAC signature, then deserialize.

    Raises ValueError if the signature does not match.
    """
    if len(signed_data) <= DIGEST_SIZE:
        raise ValueError("Payload too short")
    received_sig = signed_data[:DIGEST_SIZE]
    raw = signed_data[DIGEST_SIZE:]
    expected_sig = hmac.new(SECRET_KEY, raw, hashlib.sha256).digest()
    if not hmac.compare_digest(received_sig, expected_sig):
        raise ValueError("HMAC verification failed — data may be tampered")
    return pickle.loads(raw)  # SAFE: only reached after HMAC verification


def round_trip(obj: Any) -> Any:
    """Sign then verify — integration sanity check."""
    return verify_and_load(sign_payload(obj))
