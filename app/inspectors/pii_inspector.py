import re
from typing import Any, Dict, List, Optional
from app.inspectors.base import BaseInspector, InspectionResult, ViolationItem


class PIIInspector(BaseInspector):
    """Detects Personally Identifiable Information (PII) such as emails, phones, SSNs, credit cards, and IPs."""

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.entities = config.get("entities", [])
        self._compiled_rules = []
        for entity in self.entities:
            name = entity.get("name")
            pattern_str = entity.get("regex")
            redact_with = entity.get("redact_with", "[REDACTED]")
            if pattern_str:
                try:
                    compiled = re.compile(pattern_str, re.IGNORECASE)
                    self._compiled_rules.append(
                        {
                            "name": name,
                            "regex": compiled,
                            "redact_with": redact_with,
                        }
                    )
                except re.error:
                    pass

    async def inspect(self, text: str, context: Optional[Dict[str, Any]] = None) -> InspectionResult:
        if not self.enabled or not text:
            return InspectionResult(
                inspector_name="pii",
                passed=True,
                risk_score=0.0,
                action_suggested="ALLOW",
                sanitized_text=text,
            )

        sanitized_text = text
        violations: List[ViolationItem] = []
        entity_counts: Dict[str, int] = {}

        for rule in self._compiled_rules:
            matches = list(rule["regex"].finditer(sanitized_text))
            if matches:
                entity_name = rule["name"]
                entity_counts[entity_name] = len(matches)
                for m in matches:
                    matched_val = m.group(0)
                    # Mask value for safe reporting (e.g., j***@domain.com)
                    masked_preview = matched_val[:2] + "***" if len(matched_val) > 4 else "***"
                    violations.append(
                        ViolationItem(
                            category="pii",
                            rule_name=f"pii_{entity_name}",
                            description=f"Detected {entity_name.upper()} entity in payload.",
                            severity="MEDIUM" if entity_name in ["email", "phone", "ipv4"] else "HIGH",
                            matched_text=masked_preview,
                            score=0.4 if entity_name in ["email", "phone"] else 0.8,
                        )
                    )
                # Redact matched text
                sanitized_text = rule["regex"].sub(rule["redact_with"], sanitized_text)

        has_violations = len(violations) > 0
        risk_score = min(1.0, len(violations) * self.risk_weight) if has_violations else 0.0

        return InspectionResult(
            inspector_name="pii",
            passed=not has_violations,
            risk_score=risk_score,
            action_suggested=self.action if has_violations else "ALLOW",
            violations=violations,
            sanitized_text=sanitized_text,
            metadata={"entity_counts": entity_counts},
        )
