import asyncio
import logging
import time
from pathlib import Path
from typing import Any, Dict, List, Optional
import yaml
from pydantic import BaseModel, Field
from app.config import settings
from app.inspectors.base import BaseInspector, InspectionResult, ViolationItem
from app.inspectors.injection_inspector import PromptInjectionInspector
from app.inspectors.pii_inspector import PIIInspector
from app.inspectors.secret_inspector import SecretInspector
from app.policy.schema import PolicySchema

logger = logging.getLogger("argus.policy.engine")


class PolicyDecision(BaseModel):
    action: str  # ALLOW | BLOCKED | REDACTED | FLAGGED
    passed: bool
    risk_score: float
    sanitized_text: str
    violations: List[ViolationItem] = Field(default_factory=list)
    inspector_results: Dict[str, Any] = Field(default_factory=dict)
    execution_time_ms: float = 0.0


class PolicyEngine:
    """Evaluates security rules and risk thresholds across input and output pipelines."""

    def __init__(self, policy_path: Optional[Path] = None):
        self.policy_path = policy_path or settings.policy_full_path
        self.policy: PolicySchema = self._load_policy()
        self.inspectors: Dict[str, BaseInspector] = {}
        self._initialize_inspectors()

    def _load_policy(self) -> PolicySchema:
        if not self.policy_path.exists():
            logger.warning(f"Policy file {self.policy_path} not found. Using default empty policy schema.")
            return PolicySchema()
        try:
            with open(self.policy_path, "r", encoding="utf-8") as f:
                raw_data = yaml.safe_load(f)
                return PolicySchema(**(raw_data or {}))
        except Exception as e:
            logger.error(f"Failed to parse policy YAML at {self.policy_path}: {e}")
            return PolicySchema()

    def _initialize_inspectors(self) -> None:
        self.inspectors = {}
        inspectors_cfg = self.policy.inspectors

        if inspectors_cfg.pii and inspectors_cfg.pii.enabled:
            self.inspectors["pii"] = PIIInspector(inspectors_cfg.pii.model_dump())

        if inspectors_cfg.prompt_injection and inspectors_cfg.prompt_injection.enabled:
            self.inspectors["prompt_injection"] = PromptInjectionInspector(
                inspectors_cfg.prompt_injection.model_dump()
            )

        if inspectors_cfg.secret_leakage and inspectors_cfg.secret_leakage.enabled:
            self.inspectors["secret_leakage"] = SecretInspector(
                inspectors_cfg.secret_leakage.model_dump()
            )

    def reload_policy(self, custom_path: Optional[Path] = None) -> None:
        if custom_path:
            self.policy_path = custom_path
        self.policy = self._load_policy()
        self._initialize_inspectors()
        logger.info(f"Policy engine reloaded with {len(self.inspectors)} active inspectors.")

    async def evaluate_request(self, text: str) -> PolicyDecision:
        """Inspect and decide on incoming client prompt."""
        start_time = time.perf_counter()
        violations: List[ViolationItem] = []
        inspector_results: Dict[str, Any] = {}
        current_text = text
        max_risk = 0.0
        should_block = False
        was_redacted = False

        # Execute inspectors concurrently for low latency
        tasks = [inspector.inspect(current_text) for inspector in self.inspectors.values()]
        results: List[InspectionResult] = await asyncio.gather(*tasks, return_exceptions=False)

        for res in results:
            inspector_results[res.inspector_name] = {
                "passed": res.passed,
                "risk_score": res.risk_score,
                "action": res.action_suggested,
                "violation_count": len(res.violations),
            }
            violations.extend(res.violations)

            if res.action_suggested == "BLOCK":
                should_block = True
                max_risk = max(max_risk, res.risk_score)
            elif res.action_suggested == "REDACT":
                if res.sanitized_text and res.sanitized_text != current_text:
                    current_text = res.sanitized_text
                    was_redacted = True
                max_risk = max(max_risk, res.risk_score)
            else:
                max_risk = max(max_risk, res.risk_score)

        # Check global composite risk threshold only from blocking or flagging rules
        if max_risk >= self.policy.global_settings.risk_threshold_block and any(
            r.action_suggested == "BLOCK" for r in results
        ):
            should_block = True

        elapsed_ms = (time.perf_counter() - start_time) * 1000.0

        if should_block:
            action = "BLOCKED"
        elif was_redacted:
            action = "REDACTED"
        elif max_risk >= self.policy.global_settings.risk_threshold_flag or violations:
            action = "FLAGGED"
        else:
            action = "ALLOW"

        return PolicyDecision(
            action=action,
            passed=not should_block,
            risk_score=max_risk,
            sanitized_text=current_text,
            violations=violations,
            inspector_results=inspector_results,
            execution_time_ms=elapsed_ms,
        )

    async def evaluate_response(self, text: str) -> PolicyDecision:
        """Inspect and sanitize outgoing LLM completion."""
        start_time = time.perf_counter()
        violations: List[ViolationItem] = []
        inspector_results: Dict[str, Any] = {}
        current_text = text
        should_block = False
        was_redacted = False
        max_risk = 0.0

        # Check secret leakage in response
        if "secret_leakage" in self.inspectors:
            sec_res = await self.inspectors["secret_leakage"].inspect(current_text)
            inspector_results["secret_leakage"] = sec_res.model_dump()
            violations.extend(sec_res.violations)
            if not sec_res.passed and self.policy.response_rules.block_on_secret_leak:
                should_block = True
                max_risk = max(max_risk, sec_res.risk_score)

        # Check PII redaction in response
        if "pii" in self.inspectors and self.policy.response_rules.redact_pii_in_response:
            pii_res = await self.inspectors["pii"].inspect(current_text)
            inspector_results["pii"] = pii_res.model_dump()
            violations.extend(pii_res.violations)
            if pii_res.sanitized_text and pii_res.sanitized_text != current_text:
                current_text = pii_res.sanitized_text
                was_redacted = True
                max_risk = max(max_risk, pii_res.risk_score)

        elapsed_ms = (time.perf_counter() - start_time) * 1000.0
        action = "BLOCKED" if should_block else ("REDACTED" if was_redacted else "ALLOW")

        return PolicyDecision(
            action=action,
            passed=not should_block,
            risk_score=max_risk,
            sanitized_text=current_text,
            violations=violations,
            inspector_results=inspector_results,
            execution_time_ms=elapsed_ms,
        )


policy_engine = PolicyEngine()
