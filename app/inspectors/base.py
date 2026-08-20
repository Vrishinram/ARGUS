from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class ViolationItem(BaseModel):
    category: str  # pii | prompt_injection | secret_leakage
    rule_name: str
    description: str
    severity: str = "HIGH"  # LOW | MEDIUM | HIGH | CRITICAL
    matched_text: Optional[str] = None
    score: float = 0.0


class InspectionResult(BaseModel):
    inspector_name: str
    passed: bool = True
    risk_score: float = 0.0
    action_suggested: str = "ALLOW"  # ALLOW | REDACT | FLAG | BLOCK
    violations: List[ViolationItem] = Field(default_factory=list)
    sanitized_text: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class BaseInspector(ABC):
    """Abstract base class for all request and response inspectors."""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.enabled = config.get("enabled", True)
        self.action = config.get("action", "FLAG")
        self.risk_weight = config.get("risk_weight", 0.5)

    @abstractmethod
    async def inspect(self, text: str, context: Optional[Dict[str, Any]] = None) -> InspectionResult:
        """Inspect input text and return an InspectionResult."""
        pass
