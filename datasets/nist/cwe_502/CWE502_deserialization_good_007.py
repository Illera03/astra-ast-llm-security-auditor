"""
CWE-502: Insecure Deserialization — Safe
Pattern: ast.literal_eval() for safely parsing Python literal structures.
Reference: NIST Juliet CWE-502 safe variant.
"""
import ast


def parse_config_value(raw_value):
    try:
        return ast.literal_eval(raw_value)
    except (ValueError, SyntaxError):
        return raw_value


def load_inline_config(config_lines):
    config = {}
    for line in config_lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        key, _, value = line.partition("=")
        config[key.strip()] = parse_config_value(value.strip())
    return config


if __name__ == "__main__":
    sample = ["timeout = 30", "hosts = ['a.example.com', 'b.example.com']"]
    print(load_inline_config(sample))
