"""CWE-502 Vulnerable: pickle.load from a user-controlled file path.

If the file path comes from user input, an attacker can point to a
malicious pickle file, leading to arbitrary code execution on load.
"""

import pickle
import sys


def load_model(model_path: str) -> object:
    """Load a machine learning model from a user-specified path."""
    print(f"Loading model from: {model_path}")

    # VULNERABLE: user controls which file gets deserialized
    with open(model_path, "rb") as f:
        model = pickle.load(f)

    return model


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: script.py <model_path.pkl>")
        sys.exit(1)

    model_path = sys.argv[1]
    model = load_model(model_path)
    print(f"Model loaded: {type(model).__name__}")
