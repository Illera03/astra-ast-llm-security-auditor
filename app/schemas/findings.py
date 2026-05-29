from enum import StrEnum

from pydantic import BaseModel, Field


class SeverityLevel(StrEnum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class VulnerabilityFinding(BaseModel):
    """
    Core data model for security findings.
    Combines static AST heuristics with LLM semantic validation.
    """

    # 1. Identification
    cwe_id: str = Field(..., description="Vulnerability ID")

    # 2. Static Analysis (AST)
    file_path: str = Field(..., description="Path of the analyzed file")
    line_number: int = Field(..., description="Line of the suspicious node")
    node_type: str = Field(..., description="AST node type (e.g., Call)")
    severity: SeverityLevel = Field(..., description="Base static severity")

    # 3. Semantic Validation (LLM)
    exploit_path: str = Field(..., description="Explanation of the data flow")
    confidence: float = Field(..., ge=0.0, le=1.0, description="LLM confidence (0-1)")

    # 4. Hybrid Engine (Calculated post-inference)
    context_complexity: float | None = Field(
        default=None, description="Cyclomatic complexity"
    )
    hybrid_score: float | None = Field(default=None, description="Final risk score")
    is_false_positive: bool = Field(default=False, description="Fails 0.65 threshold")
