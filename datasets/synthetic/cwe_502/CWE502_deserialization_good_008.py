"""
CWE-502: Insecure Deserialization — Safe
Pattern: xmltodict.parse() as a safe alternative to xml.etree for config parsing.
Reference: NIST Juliet CWE-502 safe variant.
"""

import json

import xmltodict


def convert_xml_config(xml_string):
    parsed = xmltodict.parse(xml_string)
    return json.loads(json.dumps(parsed))


def load_xml_settings(path):
    with open(path) as f:
        xml_data = f.read()
    config = convert_xml_config(xml_data)
    root = config.get("settings", {})
    return {
        "debug": root.get("debug", "false") == "true",
        "log_level": root.get("log_level", "INFO"),
        "max_workers": int(root.get("max_workers", 4)),
    }
