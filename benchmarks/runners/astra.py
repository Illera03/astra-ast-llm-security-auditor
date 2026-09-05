from app.core.cache import AnalysisCache
from app.core.scoring import ScoringEngine
from app.llm.client import OllamaClient
from app.scanner import SecurityScanner
from benchmarks.metrics import classify_result
from benchmarks.schemas import DatasetEntry, EvaluationResult, ToolName


async def evaluate_file(
    entry: DatasetEntry,
    datasets_dir: str,
) -> EvaluationResult:
    file_path = f"{datasets_dir}/{entry.file}"

    scanner = SecurityScanner()
    cache = AnalysisCache()
    llm_client = OllamaClient()
    scoring_engine = ScoringEngine()

    static_results = scanner.scan_file(file_path)

    predicted = "safe"

    for finding in static_results:
        context = finding.code_snippet
        llm_response = cache.get(context)

        if not llm_response:
            llm_response = await llm_client.analyze_vulnerability(
                finding.cwe_id, context
            )
            if llm_response:
                cache.set(context, llm_response)

        if not llm_response:
            continue

        llm_risk = (
            llm_response.confidence
            if llm_response.is_exploitable
            else (1.0 - llm_response.confidence)
        )

        final_score, is_critical = scoring_engine.evaluate(
            finding=finding, llm_risk_score=llm_risk
        )

        if is_critical:
            predicted = "vulnerable"
            break

    tp, fp, tn, fn = classify_result(entry.expected, predicted)

    return EvaluationResult(
        tool=ToolName.ASTRA,
        file=entry.file,
        cwe_id=entry.cwe_id,
        expected=entry.expected,
        predicted=predicted,
        true_positive=tp,
        false_positive=fp,
        true_negative=tn,
        false_negative=fn,
    )
