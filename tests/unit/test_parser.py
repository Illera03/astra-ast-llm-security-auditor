from app.ingestion.parser import CodeParser

# ──────────────────────────────────────────────
# CWE-78: Command Injection (existing + regression)
# ──────────────────────────────────────────────


def test_parser_detects_dynamic_subprocess_call() -> None:
    """Test that the parser flags subprocess calls with dynamic variables."""
    source_code = """
import subprocess
user_input = get_user_input()
subprocess.run(f"ping -c 4 {user_input}", shell=True)
    """

    parser = CodeParser(file_path="test.py", source_code=source_code)
    findings = parser.analyze()

    assert len(findings) == 1
    assert findings[0].cwe_id == "CWE-78"
    assert findings[0].node_type == "Call"


def test_parser_ignores_static_subprocess_call() -> None:
    """Test that the parser ignores safe, hardcoded subprocess calls."""
    source_code = """
import subprocess
# This is safe because it uses a constant literal string
subprocess.run("ls -la", shell=True)
    """

    parser = CodeParser(file_path="test.py", source_code=source_code)
    findings = parser.analyze()

    assert len(findings) == 0


# ──────────────────────────────────────────────
# CWE-502: Insecure Deserialization
# ──────────────────────────────────────────────


def test_parser_detects_pickle_loads_with_dynamic_arg() -> None:
    source_code = """
import pickle

def load_data(user_data):
    return pickle.loads(user_data)
    """

    parser = CodeParser(file_path="test.py", source_code=source_code)
    findings = parser.analyze()

    assert len(findings) == 1
    assert findings[0].cwe_id == "CWE-502"
    assert findings[0].severity.value == "CRITICAL"


def test_parser_detects_pickle_load_with_dynamic_arg() -> None:
    source_code = """
import pickle

def load_file(file_obj):
    return pickle.load(file_obj)
    """

    parser = CodeParser(file_path="test.py", source_code=source_code)
    findings = parser.analyze()

    assert len(findings) == 1
    assert findings[0].cwe_id == "CWE-502"


def test_parser_detects_marshal_loads_with_dynamic_arg() -> None:
    source_code = """
import marshal

def deserialize(raw_bytes):
    return marshal.loads(raw_bytes)
    """

    parser = CodeParser(file_path="test.py", source_code=source_code)
    findings = parser.analyze()

    assert len(findings) == 1
    assert findings[0].cwe_id == "CWE-502"
    assert findings[0].severity.value == "CRITICAL"


def test_parser_detects_yaml_load_without_safe_loader() -> None:
    source_code = """
import yaml

def parse_config(data):
    return yaml.load(data)
    """

    parser = CodeParser(file_path="test.py", source_code=source_code)
    findings = parser.analyze()

    assert len(findings) == 1
    assert findings[0].cwe_id == "CWE-502"
    assert findings[0].severity.value == "HIGH"


def test_parser_ignores_yaml_load_with_safe_loader() -> None:
    source_code = """
import yaml

def parse_config(data):
    return yaml.load(data, Loader=yaml.SafeLoader)
    """

    parser = CodeParser(file_path="test.py", source_code=source_code)
    findings = parser.analyze()

    assert len(findings) == 0


def test_parser_ignores_yaml_load_with_csafe_loader() -> None:
    source_code = """
import yaml

def parse_config(data):
    return yaml.load(data, Loader=yaml.CSafeLoader)
    """

    parser = CodeParser(file_path="test.py", source_code=source_code)
    findings = parser.analyze()

    assert len(findings) == 0


def test_parser_ignores_pickle_loads_with_constant() -> None:
    source_code = """
import pickle
pickle.loads(b"constant_bytes")
    """

    parser = CodeParser(file_path="test.py", source_code=source_code)
    findings = parser.analyze()

    assert len(findings) == 0


# ──────────────────────────────────────────────
# CWE-22: Path Traversal
# ──────────────────────────────────────────────


def test_parser_detects_open_with_dynamic_path() -> None:
    source_code = """
def read_file(user_path):
    with open(user_path) as f:
        return f.read()
    """

    parser = CodeParser(file_path="test.py", source_code=source_code)
    findings = parser.analyze()

    assert len(findings) == 1
    assert findings[0].cwe_id == "CWE-22"
    assert findings[0].severity.value == "HIGH"


def test_parser_ignores_open_with_static_path() -> None:
    source_code = """
def read_config():
    with open("config.txt") as f:
        return f.read()
    """

    parser = CodeParser(file_path="test.py", source_code=source_code)
    findings = parser.analyze()

    assert len(findings) == 0


def test_parser_detects_os_remove_with_dynamic_path() -> None:
    source_code = """
import os

def delete_file(user_path):
    os.remove(user_path)
    """

    parser = CodeParser(file_path="test.py", source_code=source_code)
    findings = parser.analyze()

    assert len(findings) == 1
    assert findings[0].cwe_id == "CWE-22"
    assert findings[0].severity.value == "HIGH"


def test_parser_detects_os_path_join_with_dynamic_arg() -> None:
    source_code = """
import os

def build_path(user_input):
    return os.path.join("/tmp", user_input)
    """

    parser = CodeParser(file_path="test.py", source_code=source_code)
    findings = parser.analyze()

    assert len(findings) == 1
    assert findings[0].cwe_id == "CWE-22"
    assert findings[0].severity.value == "MEDIUM"


def test_parser_detects_pathlib_path_with_dynamic_arg() -> None:
    source_code = """
from pathlib import Path

def get_path(user_input):
    return Path(user_input)
    """

    parser = CodeParser(file_path="test.py", source_code=source_code)
    findings = parser.analyze()

    assert len(findings) == 1
    assert findings[0].cwe_id == "CWE-22"
    assert findings[0].severity.value == "MEDIUM"


def test_parser_ignores_pathlib_path_with_static_arg() -> None:
    source_code = """
from pathlib import Path

def get_config():
    return Path("config.txt")
    """

    parser = CodeParser(file_path="test.py", source_code=source_code)
    findings = parser.analyze()

    assert len(findings) == 0


def test_parser_detects_path_read_text_chained_call() -> None:
    source_code = """
from pathlib import Path

def read_user_file(user_input):
    return Path(user_input).read_text()
    """

    parser = CodeParser(file_path="test.py", source_code=source_code)
    findings = parser.analyze()

    cwe22_findings = [f for f in findings if f.cwe_id == "CWE-22"]
    high_findings = [f for f in cwe22_findings if f.severity.value == "HIGH"]
    assert len(high_findings) >= 1


def test_parser_ignores_path_read_text_with_static_arg() -> None:
    source_code = """
from pathlib import Path

def read_config():
    return Path("config.txt").read_text()
    """

    parser = CodeParser(file_path="test.py", source_code=source_code)
    findings = parser.analyze()

    high_findings = [
        f for f in findings if f.cwe_id == "CWE-22" and f.severity.value == "HIGH"
    ]
    assert len(high_findings) == 0


def test_parser_detects_io_open_with_dynamic_path() -> None:
    source_code = """
import io

def read_file(user_path):
    return io.open(user_path)
    """

    parser = CodeParser(file_path="test.py", source_code=source_code)
    findings = parser.analyze()

    assert len(findings) == 1
    assert findings[0].cwe_id == "CWE-22"
    assert findings[0].severity.value == "HIGH"


# ──────────────────────────────────────────────
# Multi-CWE detection in a single file
# ──────────────────────────────────────────────


def test_parser_detects_multiple_cwes_in_one_file() -> None:
    source_code = """
import subprocess
import pickle

def inject(cmd):
    subprocess.run(cmd, shell=True)

def deserialize(data):
    return pickle.loads(data)

def read(user_path):
    with open(user_path) as f:
        return f.read()
    """

    parser = CodeParser(file_path="test.py", source_code=source_code)
    findings = parser.analyze()

    cwe_ids = {f.cwe_id for f in findings}
    assert "CWE-78" in cwe_ids
    assert "CWE-502" in cwe_ids
    assert "CWE-22" in cwe_ids
    assert len(findings) == 3
