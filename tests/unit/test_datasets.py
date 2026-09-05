import ast
from collections import Counter
from pathlib import Path

import yaml

DATASETS_DIR = Path(__file__).resolve().parent.parent.parent / "datasets"
MANIFEST_PATH = DATASETS_DIR / "manifest.yaml"


def _load_manifest() -> list[dict[str, str]]:
    result: list[dict[str, str]] = yaml.safe_load(MANIFEST_PATH.read_text())
    return result


def test_manifest_is_valid_yaml() -> None:
    entries = _load_manifest()
    assert isinstance(entries, list)
    assert len(entries) > 0


def test_all_manifest_files_exist() -> None:
    entries = _load_manifest()
    missing = []
    for entry in entries:
        file_path = DATASETS_DIR / entry["file"]
        if not file_path.exists():
            missing.append(entry["file"])
    assert missing == [], f"Missing files: {missing}"


def test_manifest_entries_have_required_fields() -> None:
    entries = _load_manifest()
    required = {"file", "cwe_id", "expected", "source"}
    for entry in entries:
        missing_fields = required - set(entry.keys())
        assert missing_fields == set(), (
            f"{entry.get('file', '?')} missing fields: {missing_fields}"
        )


def test_dataset_file_count() -> None:
    entries = _load_manifest()
    assert len(entries) == 160


def test_dataset_source_distribution() -> None:
    entries = _load_manifest()
    source_counts = Counter(e["source"] for e in entries)
    assert source_counts["synthetic"] == 150, (
        f"synthetic has {source_counts['synthetic']} files, expected 150"
    )
    assert source_counts["external_bandit"] == 10, (
        f"external_bandit has {source_counts['external_bandit']} files, expected 10"
    )


def test_all_dataset_files_are_valid_python() -> None:
    entries = _load_manifest()
    errors = []
    for entry in entries:
        file_path = DATASETS_DIR / entry["file"]
        try:
            ast.parse(file_path.read_text())
        except SyntaxError as e:
            errors.append(f"{entry['file']}: {e}")
    assert errors == [], "Syntax errors:\n" + "\n".join(errors)


def test_expected_values_are_valid() -> None:
    entries = _load_manifest()
    for entry in entries:
        assert entry["expected"] in ("vulnerable", "safe"), (
            f"{entry['file']} has invalid expected: {entry['expected']}"
        )


def test_cwe_ids_are_valid() -> None:
    entries = _load_manifest()
    valid_cwes = {"CWE-78", "CWE-22", "CWE-502"}
    for entry in entries:
        assert entry["cwe_id"] in valid_cwes, (
            f"{entry['file']} has invalid cwe_id: {entry['cwe_id']}"
        )
