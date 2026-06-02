from app.core.scoring import ScoringEngine
from app.schemas.findings import SeverityLevel, VulnerabilityFinding


def test_evaluate_threshold_filtering() -> None:
    engine = ScoringEngine()

    # We simulate a finding coming from the AST with its precomputed scores
    finding = VulnerabilityFinding(
        cwe_id="CWE-78",
        file_path="fake.py",
        line_number=1,
        node_type="Call",
        severity=SeverityLevel.HIGH,
        exploit_path="Test",
        confidence=0.0,
        heuristic_score=1.0,  # AST Heurístico
        context_complexity=0.2,  # Código simple
    )

    # Scenario 1: LLM says Dangerous (0.9)
    # (0.4 * 1.0) + (0.4 * 0.9) + (0.2 * 0.2) = 0.4 + 0.36 + 0.04 = 0.80 -> PASSED
    score_high, is_crit_high = engine.evaluate(finding, llm_risk_score=0.9)
    assert score_high == 0.80
    assert is_crit_high is True

    # Scenario 2: LLM says Safe (0.1)
    # (0.4 * 1.0) + (0.4 * 0.1) + (0.2 * 0.2) = 0.4 + 0.04 + 0.04 = 0.48 -> FILTERED
    score_low, is_crit_low = engine.evaluate(finding, llm_risk_score=0.1)
    assert score_low == 0.48
    assert is_crit_low is False
