from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, Field


class ToolName(StrEnum):
    ASTRA = "astra"
    BANDIT = "bandit"
    SEMGREP = "semgrep"


class DatasetEntry(BaseModel):
    file: str
    cwe_id: str
    expected: Literal["vulnerable", "safe"]
    source: str
    description: str = ""


class EvaluationResult(BaseModel):
    tool: ToolName
    file: str
    cwe_id: str
    expected: str
    predicted: str
    score: float | None = None
    true_positive: bool = False
    false_positive: bool = False
    true_negative: bool = False
    false_negative: bool = False


class BenchmarkSummary(BaseModel):
    tool: ToolName
    source: str = Field(default="all")
    cwe_id: str = Field(default="all")
    precision: float = 0.0
    recall: float = 0.0
    f1_score: float = 0.0
    total: int = 0
    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0
