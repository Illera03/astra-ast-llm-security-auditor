import pytest
from pydantic import ValidationError

from app.schemas.findings import SeverityLevel, VulnerabilityFinding


def test_valid_vulnerability_finding() -> None:
    """Test that the model accepts valid data correctly."""
    finding = VulnerabilityFinding(
        cwe_id="CWE-89",
        file_path="src/api.py",
        line_number=42,
        node_type="Call",
        severity=SeverityLevel.HIGH,
        exploit_path="User input reaches SQL query without sanitization",
        confidence=0.9,
    )

    assert finding.cwe_id == "CWE-89"
    assert finding.severity == SeverityLevel.HIGH
    assert finding.is_false_positive is False  # Default must be False


def test_invalid_confidence_raises_error() -> None:
    """Test that Pydantic blocks confidence greater than 1.0."""
    with pytest.raises(ValidationError):
        VulnerabilityFinding(
            cwe_id="CWE-89",
            file_path="src/api.py",
            line_number=42,
            node_type="Call",
            severity=SeverityLevel.HIGH,
            exploit_path="Test exploit",
            confidence=1.5,  # THIS MUST FAIL (maximum is 1.0)
        )
