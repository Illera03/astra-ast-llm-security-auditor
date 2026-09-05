"""
CWE-502: Insecure Deserialization — Safe
Pattern: Restricted Unpickler that only allows whitelisted classes.
Reference: Python docs recommendation for safe pickle usage.
"""
import pickle
import io


ALLOWED_CLASSES = {
    ("builtins", "dict"),
    ("builtins", "list"),
    ("builtins", "set"),
    ("builtins", "tuple"),
    ("builtins", "str"),
    ("builtins", "int"),
    ("builtins", "float"),
    ("builtins", "bool"),
}


class RestrictedUnpickler(pickle.Unpickler):
    def find_class(self, module, name):
        if (module, name) in ALLOWED_CLASSES:
            return super().find_class(module, name)
        raise pickle.UnpicklingError(
            f"Forbidden class: {module}.{name}"
        )


def safe_pickle_loads(data):
    return RestrictedUnpickler(io.BytesIO(data)).load()
