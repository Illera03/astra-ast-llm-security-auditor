"""CWE-502 Safe: pickle.loads on a hardcoded constant byte literal.

Pattern: The pickled data is a compile-time constant embedded in the source.
No external input influences the bytes, so deserialization is safe.
Bandit flags all pickle.loads calls regardless of data source.
Classification: safe
"""

import pickle

SERIALIZED_DEFAULTS = (
    b"\x80\x04\x95\x17\x00\x00\x00\x00\x00\x00\x00}"
    b"\x94\x8c\x05level\x94\x8c\x04INFO\x94s."
)


def get_default_logging_config() -> dict:
    config = pickle.loads(SERIALIZED_DEFAULTS)
    config.setdefault("format", "%(message)s")
    config.setdefault("handlers", ["console"])
    return config


if __name__ == "__main__":
    defaults = get_default_logging_config()
    print(defaults)
