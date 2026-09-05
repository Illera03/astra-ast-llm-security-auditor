import tempfile
from pathlib import Path

from benchmarks.evaluate import load_manifest
from benchmarks.schemas import DatasetEntry


def test_load_manifest_parses_valid_yaml() -> None:
    content = """
- file: "industry/cwe_78/test.py"
  cwe_id: "CWE-78"
  expected: "vulnerable"
  source: "industry"
  description: "test case"
- file: "industry/cwe_22/safe.py"
  cwe_id: "CWE-22"
  expected: "safe"
  source: "industry"
  description: "safe case"
"""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        f.write(content)
        f.flush()

        entries = load_manifest(f.name)

    assert len(entries) == 2
    assert isinstance(entries[0], DatasetEntry)
    assert entries[0].cwe_id == "CWE-78"
    assert entries[0].expected == "vulnerable"
    assert entries[1].expected == "safe"

    Path(f.name).unlink()
