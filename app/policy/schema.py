from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class EntityRule(BaseModel):
    name: str
    regex: str
    redact_with: str = "[REDACTED]"


class PIIInspectorConfig(BaseModel):
    enabled: bool = True
    action: str = "REDACT"  # REDACT | BLOCK | FLAG | ALLOW
    risk_weight: float = 0.30
    entities: List[EntityRule] = Field(default_factory=list)


class InjectionPattern(BaseModel):
    name: str
    pattern: str
    score: float = 0.80
    description: Optional[str] = "Injection pattern"


class InjectionInspectorConfig(BaseModel):
    enabled: bool = True
    action: str = "BLOCK"  # BLOCK | FLAG | ALLOW
    risk_weight: float = 0.85
    block_threshold: float = 0.60
    patterns: List[InjectionPattern] = Field(default_factory=list)


class SecretPattern(BaseModel):
    name: str
    regex: str
    description: Optional[str] = "Secret pattern"


class SecretInspectorConfig(BaseModel):
    enabled: bool = True
    action: str = "BLOCK"  # BLOCK | FLAG | ALLOW
    risk_weight: float = 0.95
    patterns: List[SecretPattern] = Field(default_factory=list)


class InspectorsConfig(BaseModel):
    pii: Optional[PIIInspectorConfig] = None
    prompt_injection: Optional[InjectionInspectorConfig] = None
    secret_leakage: Optional[SecretInspectorConfig] = None


class GlobalSettings(BaseModel):
    default_action: str = "ALLOW"
    risk_threshold_block: float = 0.70
    risk_threshold_flag: float = 0.40
    enable_response_inspection: bool = True
    enable_request_redaction: bool = True


class ResponseRules(BaseModel):
    block_on_secret_leak: bool = True
    redact_pii_in_response: bool = True


class PolicySchema(BaseModel):
    version: str = "1.0"
    metadata: Dict[str, Any] = Field(default_factory=dict)
    global_settings: GlobalSettings = Field(default_factory=GlobalSettings)
    inspectors: InspectorsConfig = Field(default_factory=InspectorsConfig)
    response_rules: ResponseRules = Field(default_factory=ResponseRules)
