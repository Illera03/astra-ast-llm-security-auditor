"""CWE-22 | VULNERABLE | Path constructed through multiple function calls.
User input flows through get_base(), get_subpath(), and os.path.join without
any validation or sanitization at any stage.
Edge case: multi-hop data flow challenges taint tracking in AST analysis.
"""
import os


def get_base(tenant_id: str) -> str:
    return f"/data/tenants/{tenant_id}"


def get_subpath(category: str, filename: str) -> str:
    return os.path.join(category, filename)


def build_full_path(tenant_id: str, category: str, filename: str) -> str:
    base = get_base(tenant_id)
    sub = get_subpath(category, filename)
    return os.path.join(base, sub)


def read_tenant_file(
    tenant_id: str, category: str, filename: str
) -> str | None:
    full_path = build_full_path(tenant_id, category, filename)
    try:
        with open(full_path) as fh:
            return fh.read()
    except FileNotFoundError:
        return None


if __name__ == "__main__":
    import sys
    content = read_tenant_file(sys.argv[1], sys.argv[2], sys.argv[3])
    if content:
        print(content)
