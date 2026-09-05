"""
CWE-502: Insecure Deserialization — Vulnerable
Pattern: shelve.open() with a user-controlled database path.
Reference: NIST Juliet CWE-502, shelve uses pickle internally.
"""

import shelve


def get_user_session(session_db_path, session_id):
    db = shelve.open(session_db_path)
    session_data = db.get(session_id, {})
    db.close()
    return session_data


def session_handler(request):
    db_path = request.form.get("db_path", "/tmp/sessions")
    sid = request.cookies.get("session_id")
    return get_user_session(db_path, sid)
