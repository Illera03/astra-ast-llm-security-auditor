import json
import subprocess
from pathlib import Path

from benchmarks.metrics import classify_result
from benchmarks.schemas import DatasetEntry, EvaluationResult, ToolName


def run_bandit(datasets_dir: str) -> dict[str, list[dict[str, str]]]:
    """Run bandit once on the entire datasets directory and return findings by file."""
    try:
        result = subprocess.run(
            ["bandit", "-r", datasets_dir, "-f", "json", "-q"],
            capture_output=True,
            text=True,
            timeout=300,
        )
    except FileNotFoundError:
        print("[!] bandit not found. Install with: pip install bandit")
        return {}

    findings_by_file: dict[str, list[dict[str, str]]] = {}

    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        return findings_by_file

    for finding in data.get("results", []):
        filepath = str(Path(finding["filename"]).resolve())
        findings_by_file.setdefault(filepath, []).append(finding)

    return findings_by_file


def evaluate_entries(
    entries: list[DatasetEntry],
    datasets_dir: str,
) -> list[EvaluationResult]:
    findings_by_file = run_bandit(datasets_dir)
    results: list[EvaluationResult] = []

    for entry in entries:
        resolved = str(Path(f"{datasets_dir}/{entry.file}").resolve())
        file_findings = findings_by_file.get(resolved, [])

        medium_or_above = [
            f for f in file_findings
            if f.get("issue_severity", "LOW") in ("MEDIUM", "HIGH")
        ]

        predicted = "vulnerable" if medium_or_above else "safe"
        tp, fp, tn, fn = classify_result(entry.expected, predicted)

        results.append(EvaluationResult(
            tool=ToolName.BANDIT,
            file=entry.file,
            cwe_id=entry.cwe_id,
            expected=entry.expected,
            predicted=predicted,
            true_positive=tp,
            false_positive=fp,
            true_negative=tn,
            false_negative=fn,
        ))

    return results
