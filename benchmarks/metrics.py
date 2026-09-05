from collections import defaultdict

from benchmarks.schemas import BenchmarkSummary, EvaluationResult, ToolName


def classify_result(expected: str, predicted: str) -> tuple[bool, bool, bool, bool]:
    tp = expected == "vulnerable" and predicted == "vulnerable"
    fp = expected == "safe" and predicted == "vulnerable"
    tn = expected == "safe" and predicted == "safe"
    fn = expected == "vulnerable" and predicted == "safe"
    return tp, fp, tn, fn


def calculate_metrics(
    tool: ToolName,
    results: list[EvaluationResult],
    source: str = "all",
    cwe_id: str = "all",
) -> BenchmarkSummary:
    tp = sum(1 for r in results if r.true_positive)
    fp = sum(1 for r in results if r.false_positive)
    tn = sum(1 for r in results if r.true_negative)
    fn = sum(1 for r in results if r.false_negative)

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (
        2 * precision * recall / (precision + recall)
        if (precision + recall) > 0
        else 0.0
    )

    return BenchmarkSummary(
        tool=tool,
        source=source,
        cwe_id=cwe_id,
        precision=round(precision, 4),
        recall=round(recall, 4),
        f1_score=round(f1, 4),
        total=len(results),
        tp=tp,
        fp=fp,
        tn=tn,
        fn=fn,
    )


def group_and_calculate(
    results: list[EvaluationResult],
) -> list[BenchmarkSummary]:
    summaries: list[BenchmarkSummary] = []

    groups: dict[tuple[ToolName, str, str], list[EvaluationResult]] = defaultdict(list)
    tool_groups: dict[ToolName, list[EvaluationResult]] = defaultdict(list)

    for r in results:
        groups[(r.tool, r.cwe_id, "all")].append(r)
        tool_groups[r.tool].append(r)

    for (tool, cwe_id, source), group_results in sorted(groups.items()):
        summaries.append(calculate_metrics(tool, group_results, source, cwe_id))

    for tool, tool_results in sorted(tool_groups.items()):
        summaries.append(calculate_metrics(tool, tool_results, "all", "all"))

    return summaries
