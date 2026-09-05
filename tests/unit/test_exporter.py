import csv
import tempfile
from pathlib import Path

from benchmarks.exporter import export_csv, export_table
from benchmarks.schemas import BenchmarkSummary, ToolName


def _make_summary() -> BenchmarkSummary:
    return BenchmarkSummary(
        tool=ToolName.ASTRA,
        source="all",
        cwe_id="all",
        precision=0.85,
        recall=0.90,
        f1_score=0.8744,
        total=100,
        tp=45,
        fp=8,
        tn=42,
        fn=5,
    )


def test_export_csv_creates_valid_file() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        path = f"{tmpdir}/results.csv"
        export_csv([_make_summary()], path)

        assert Path(path).exists()
        with open(path) as f:
            reader = csv.reader(f)
            headers = next(reader)
            assert "tool" in headers
            assert "precision" in headers
            assert "recall" in headers
            assert "f1_score" in headers

            rows = list(reader)
            assert len(rows) == 1


def test_export_table_contains_headers() -> None:
    table = export_table([_make_summary()])
    assert "Precision" in table
    assert "Recall" in table
    assert "F1" in table
    assert "astra" in table
