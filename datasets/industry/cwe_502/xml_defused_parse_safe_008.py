"""CWE-502 Safe: XML parsing with safe settings to prevent XXE attacks.

Uses xml.etree.ElementTree with a hardcoded, trusted XML string.
While XML parsing can be risky with external entities, parsing a static
known document is safe.
"""

import xml.etree.ElementTree as ET


STATIC_CONFIG_XML = """<?xml version="1.0"?>
<config>
    <database>
        <host>localhost</host>
        <port>5432</port>
        <name>myapp</name>
    </database>
    <cache>
        <backend>redis</backend>
        <ttl>300</ttl>
    </cache>
</config>
"""


def parse_static_config() -> dict:
    """Parse the embedded static XML configuration."""
    root = ET.fromstring(STATIC_CONFIG_XML)
    config = {}
    for section in root:
        config[section.tag] = {}
        for item in section:
            config[section.tag][item.tag] = item.text
    return config


if __name__ == "__main__":
    cfg = parse_static_config()
    for section, values in cfg.items():
        print(f"[{section}] {values}")
