"""
CWE-502: Insecure Deserialization — Vulnerable
Pattern: pickle.load() on a user-specified file path.
Reference: NIST Juliet CWE-502.
"""

import pickle


def load_model(model_path):
    with open(model_path, "rb") as f:
        model = pickle.load(f)
    return model


def predict(request):
    user_model_path = request.args.get("model")
    model = load_model(user_model_path)
    features = request.json.get("features")
    return model.predict([features])
