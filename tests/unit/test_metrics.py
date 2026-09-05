from benchmarks.metrics import calculate_metrics, classify_result
from benchmarks.schemas import EvaluationResult, ToolName


def _make_result(
    expected: str, predicted: str, cwe_id: str = "CWE-78"
) -> EvaluationResult:
    tp, fp, tn, fn = classify_result(expected, predicted)
    return EvaluationResult(
        tool=ToolName.ASTRA,
        file="test.py",
        cwe_id=cwe_id,
        expected=expected,
        predicted=predicted,
        true_positive=tp,
        false_positive=fp,
        true_negative=tn,
        false_negative=fn,
    )


def test_classify_true_positive() -> None:
    tp, fp, tn, fn = classify_result("vulnerable", "vulnerable")
    assert (tp, fp, tn, fn) == (True, False, False, False)


def test_classify_false_positive() -> None:
    tp, fp, tn, fn = classify_result("safe", "vulnerable")
    assert (tp, fp, tn, fn) == (False, True, False, False)


def test_classify_true_negative() -> None:
    tp, fp, tn, fn = classify_result("safe", "safe")
    assert (tp, fp, tn, fn) == (False, False, True, False)


def test_classify_false_negative() -> None:
    tp, fp, tn, fn = classify_result("vulnerable", "safe")
    assert (tp, fp, tn, fn) == (False, False, False, True)


def test_calculate_metrics_perfect_score() -> None:
    results = [
        _make_result("vulnerable", "vulnerable"),
        _make_result("vulnerable", "vulnerable"),
        _make_result("safe", "safe"),
        _make_result("safe", "safe"),
    ]
    summary = calculate_metrics(ToolName.ASTRA, results)
    assert summary.precision == 1.0
    assert summary.recall == 1.0
    assert summary.f1_score == 1.0
    assert summary.tp == 2
    assert summary.tn == 2


def test_calculate_metrics_all_false_positives() -> None:
    results = [
        _make_result("safe", "vulnerable"),
        _make_result("safe", "vulnerable"),
    ]
    summary = calculate_metrics(ToolName.ASTRA, results)
    assert summary.precision == 0.0
    assert summary.fp == 2


def test_calculate_metrics_handles_empty_list() -> None:
    summary = calculate_metrics(ToolName.ASTRA, [])
    assert summary.precision == 0.0
    assert summary.recall == 0.0
    assert summary.f1_score == 0.0
    assert summary.total == 0
