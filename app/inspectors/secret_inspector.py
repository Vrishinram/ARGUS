import re
from typing import Any, Dict, List, Optional
from app.inspectors.base import BaseInspector, InspectionResult, ViolationItem


class SecretInspector(BaseInspector):
    """Inspects payloads to prevent confidential credentials, tokens, and API keys from leaking."""

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.patterns = config.get("patterns", [])
        self._compiled_patterns = []

        for p in self.patterns:
            regex_str = p.get("regex")
            name = p.get("name", "unknown_secret")
            desc = p.get("description", "Secret token pattern matched")
            if regex_str:
                try:
                    compiled = re.compile(regex_str, re.MULTILINE)
                    self._compiled_patterns.append(
                        {
                            "name": name,
                            "regex": compiled,
                            "description": desc,
                        }
                    )
                except re.error:
                    pass

    async def inspect(self, text: str, context: Optional[Dict[str, Any]] = None) -> InspectionResult:
        if not self.enabled or not text:
            return InspectionResult(
                inspector_name="secret_leakage",
                passed=True,
                risk_score=0.0,
                action_suggested="ALLOW",
                sanitized_text=text,
            )

        violations: List[ViolationItem] = []

        for pat in self._compiled_patterns:
            matches = list(pat["regex"].finditer(text))
            if matches:
                for m in matches:
                    raw_secret = m.group(0)
                    masked = raw_secret[:4] + "..." + raw_secret[-4:] if len(raw_secret) > 8 else "****"
                    violations.append(
                        ViolationItem(
                            category="secret_leakage",
                            rule_name=pat["name"],
                            description=pat["description"],
                            severity="CRITICAL",
                            matched_text=masked,
                            score=1.0,
                        )
                    )

        has_violations = len(violations) > 0
        risk_score = 1.0 if has_violations else 0.0

        return InspectionResult(
            inspector_name="secret_leakage",
            passed=not has_violations,
            risk_score=risk_score,
            action_suggested=self.action if has_violations else "ALLOW",
            violations=violations,
            sanitized_text=text,
            metadata={"secret_matches_count": len(violations)},
        )
