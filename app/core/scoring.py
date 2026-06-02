from app.schemas.findings import VulnerabilityFinding


class ScoringEngine:
    """
    Applies the mathematical formula defined in SRS v3:
    40% Heuristic (AST) + 40% Semantic (LLM) + 20% Context Complexity.
    """

    CRITICAL_THRESHOLD = 0.65

    def evaluate(
        self, finding: VulnerabilityFinding, llm_risk_score: float
    ) -> tuple[float, bool]:
        """
        Applies the formula and determines if the finding passes the critical threshold.
        Returns (final_score, is_critical).
        """
        final_risk = (
            (0.4 * finding.heuristic_score)
            + (0.4 * llm_risk_score)
            + (0.2 * finding.context_complexity)
        )

        final_risk = round(final_risk, 3)
        is_critical = final_risk >= self.CRITICAL_THRESHOLD

        return final_risk, is_critical
