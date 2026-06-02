import os

from app.ingestion.parser import CodeParser
from app.schemas.findings import VulnerabilityFinding


class SecurityScanner:
    """
    Orchestrates the static analysis phase.
    Uses the AST parser to detect vulnerabilities and extract their exact function
    context natively.
    """

    def scan_file(self, file_path: str) -> list[VulnerabilityFinding]:
        """
        Scans a single file and returns a list of findings with their embedded context.
        """
        if not os.path.exists(file_path):
            return []

        with open(file_path, encoding="utf-8") as f:
            source_code = f.read()

        # Detect vulnerabilities and extract context natively using the AST Parser
        parser = CodeParser(file_path=file_path, source_code=source_code)
        findings = parser.analyze()

        return findings
