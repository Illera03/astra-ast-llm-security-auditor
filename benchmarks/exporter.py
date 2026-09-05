import csv
import json
from pathlib import Path

from benchmarks.schemas import BenchmarkSummary, EvaluationResult


def export_csv(summaries: list[BenchmarkSummary], output_path: str) -> None:
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            "tool", "source", "cwe_id",
            "precision", "recall", "f1_score",
            "tp", "fp", "tn", "fn", "total",
        ])
        for s in summaries:
            writer.writerow([
                s.tool, s.source, s.cwe_id,
                s.precision, s.recall, s.f1_score,
                s.tp, s.fp, s.tn, s.fn, s.total,
            ])


def export_table(summaries: list[BenchmarkSummary]) -> str:
    header = (
        f"{'Tool':<10} {'Source':<10} {'CWE':<10} "
        f"{'Precision':>9} {'Recall':>9} {'F1':>9} "
        f"{'TP':>4} {'FP':>4} {'TN':>4} {'FN':>4} {'Total':>5}"
    )
    sep = "-" * len(header)
    lines = [sep, header, sep]

    for s in summaries:
        lines.append(
            f"{s.tool:<10} {s.source:<10} {s.cwe_id:<10} "
            f"{s.precision:>9.4f} {s.recall:>9.4f} {s.f1_score:>9.4f} "
            f"{s.tp:>4} {s.fp:>4} {s.tn:>4} {s.fn:>4} {s.total:>5}"
        )

    lines.append(sep)
    return "\n".join(lines)


def export_json(
    results: list[EvaluationResult],
    summaries: list[BenchmarkSummary],
    output_path: str,
) -> None:
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    data = {
        "results": [r.model_dump() for r in results],
        "summaries": [s.model_dump() for s in summaries],
    }
    with open(output_path, "w") as f:
        json.dump(data, f, indent=2)
