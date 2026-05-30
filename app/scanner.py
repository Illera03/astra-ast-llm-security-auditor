import os

from app.ingestion.context import ContextExtractor
from app.ingestion.parser import CodeParser
from app.schemas.findings import VulnerabilityFinding


class SecurityScanner:
    """
    Orchestrates the static analysis phase.
    Combines the AST parser for detection and the Context Extractor for LLM prep.
    """

    def __init__(self, context_window: int = 10) -> None:
        self.context_extractor = ContextExtractor(window_size=context_window)

    def scan_file(self, file_path: str) -> list[tuple[VulnerabilityFinding, str]]:
        """
        Scans a single file and returns a list of findings paired with their context.
        """
        if not os.path.exists(file_path):
            return []

        with open(file_path, encoding="utf-8") as f:
            source_code = f.read()

        # Detect vulnerabilities using the AST Parser
        parser = CodeParser(file_path=file_path, source_code=source_code)
        findings = parser.analyze()

        results: list[tuple[VulnerabilityFinding, str]] = []

        # Extract context for each finding
        for finding in findings:
            context = self.context_extractor.extract(
                file_path=file_path, target_line=finding.line_number
            )
            results.append((finding, context))

        return results
