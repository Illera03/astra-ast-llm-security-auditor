"""CWE-502 Vulnerable: marshal.loads on raw bytes from an external source.

The marshal module can deserialize code objects, which can be executed.
Loading marshal data from untrusted external sources is dangerous.
"""

import marshal
import sys


def load_compiled_plugin(plugin_path: str) -> object:
    """Load a compiled Python plugin from an external file."""
    with open(plugin_path, "rb") as f:
        raw_bytes = f.read()

    # VULNERABLE: deserializing untrusted marshal data can yield code objects
    code_obj = marshal.loads(raw_bytes)
    return code_obj


def execute_plugin(plugin_path: str) -> None:
    """Load and execute an externally-provided compiled plugin."""
    code = load_compiled_plugin(plugin_path)
    exec(code)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: script.py <plugin.pyc>")
        sys.exit(1)

    execute_plugin(sys.argv[1])
