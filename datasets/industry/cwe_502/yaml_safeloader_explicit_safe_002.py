"""CWE-502 Safe: yaml.load() with explicit SafeLoader.

Pattern: yaml.load(data, Loader=yaml.SafeLoader) is safe because SafeLoader
prevents arbitrary object instantiation. Bandit flags yaml.load calls but
this usage is secure.
Classification: safe
"""
import yaml


def parse_deployment_manifest(manifest_text: str) -> dict:
    doc = yaml.load(manifest_text, Loader=yaml.SafeLoader)
    services = doc.get("services", [])
    return {
        "service_count": len(services),
        "services": services,
        "version": doc.get("version", "1.0"),
    }


if __name__ == "__main__":
    sample = """
    version: "2.0"
    services:
      - name: api
        replicas: 3
      - name: worker
        replicas: 2
    """
    result = parse_deployment_manifest(sample)
    print(result)
