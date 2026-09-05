"""
CWE-502: Insecure Deserialization — Safe
Pattern: yaml.load() with explicit SafeLoader argument.
Reference: Remediation for CVE-2017-18342, CVE-2020-1747 (PyYAML).
"""
import yaml


def parse_deployment_manifest(manifest_text):
    docs = list(yaml.load_all(manifest_text, Loader=yaml.SafeLoader))
    services = []
    for doc in docs:
        if doc and doc.get("kind") == "Service":
            services.append(doc["metadata"]["name"])
    return services


def read_manifest(path):
    with open(path, "r") as f:
        return parse_deployment_manifest(f.read())
