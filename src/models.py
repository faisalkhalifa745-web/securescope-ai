from typing import Literal
from pydantic import BaseModel, Field

Risk = Literal["Informational", "Low", "Medium", "High"]
Likelihood = Literal["low", "medium", "high"]


class Finding(BaseModel):
    id: str
    target: str = ""
    name: str
    url: str
    method: str = "GET"
    param: str = ""
    zap_risk: Risk
    zap_confidence: str = "Medium"
    cwe_id: int = 0
    plugin_id: str = ""
    description: str = ""
    solution: str = ""
    evidence: str = ""
    attack: str = ""
    message_id: str = ""
    request_snippet: str = ""
    response_snippet: str = ""
    instances: int = 1
    other_urls: list[str] = Field(default_factory=list)
    source: Literal["passive", "active"] = "passive"


class Assessment(BaseModel):
    finding_id: str
    likelihood: Likelihood
    false_positive_suspected: bool = False
    reasoning: str
    remediation: str
    needs_active_verification: bool = False
    verification_reason: str = ""
    steps_used: int = 0
    tools_used: list[str] = Field(default_factory=list)
    fallback: bool = False


class Decision(BaseModel):
    finding_id: str
    decision: Literal["approve", "reject", "modify"]
    note: str = ""
    final_likelihood: Likelihood | None = None
    approve_active_verification: bool = False


class ReviewItem(BaseModel):
    finding: Finding
    assessment: Assessment
    score: float = 0.0
    decision: Decision | None = None
