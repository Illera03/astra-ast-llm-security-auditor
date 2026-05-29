from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field

class SeverityLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class VulnerabilityFinding(BaseModel):
    """
    Main data model for security findings.
    Combines static AST information with LLM semantic validation.
    """
    # 1. Identification
    cwe_id: str = Field(..., description="Vulnerability ID (e.g. CWE-78, CWE-89)")
    
    # 2. Static Analysis (AST)
    file_path: str = Field(..., description="Path of the analyzed file")
    line_number: int = Field(..., description="Line where the suspicious node was found")
    node_type: str = Field(..., description="AST node type (e.g. Call, Attribute)")
    severity: SeverityLevel = Field(..., description="Base severity according to static heuristics")
    
    # 3. LLM Validation
    exploit_path: str = Field(..., description="Semantic explanation of how data reaches the vulnerability")
    confidence: float = Field(..., ge=0.0, le=1.0, description="LLM confidence in the exploit's viability (0.0 to 1.0)")
    
    # 4. Additional Metadata
    context_complexity: Optional[float] = Field(default=None, description="Cyclomatic complexity of the fragment")
    hybrid_score: Optional[float] = Field(default=None, description="Final weighted risk score")
    is_false_positive: bool = Field(default=False, description="True if it does not exceed the 0.65 threshold")