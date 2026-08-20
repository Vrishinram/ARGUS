import re
from typing import Any, Dict, List, Optional
from app.inspectors.base import BaseInspector, InspectionResult, ViolationItem


class PromptInjectionInspector(BaseInspector):
    """Inspects prompts for adversarial jailbreaks, instruction overrides, system extractions, and delimiter fakes."""

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.block_threshold = config.get("block_threshold", 0.60)
        self.patterns = config.get("patterns", [])
        self._compiled_patterns = []

        for p in self.patterns:
            pattern_str = p.get("pattern")
            name = p.get("name", "unknown_injection")
            score = p.get("score", 0.8)
            description = p.get("description", "Prompt injection pattern match")
            if pattern_str:
                try:
                    compiled = re.compile(pattern_str, re.IGNORECASE)
                    self._compiled_patterns.append(
                        {
                            "name": name,
                            "regex": compiled,
                            "score": score,
                            "description": description,
                        }
                    )
                except re.error:
                    pass

    async def inspect(self, text: str, context: Optional[Dict[str, Any]] = None) -> InspectionResult:
        if not self.enabled or not text:
            return InspectionResult(
                inspector_name="prompt_injection",
                passed=True,
                risk_score=0.0,
                action_suggested="ALLOW",
                sanitized_text=text,
            )

        violations: List[ViolationItem] = []
        max_score = 0.0

        for pat in self._compiled_patterns:
            matches = list(pat["regex"].finditer(text))
            if matches:
                matched_snippet = matches[0].group(0)[:40]
                item_score = pat["score"]
                max_score = max(max_score, item_score)

                severity = "CRITICAL" if item_score >= 0.85 else "HIGH" if item_score >= 0.65 else "MEDIUM"
                violations.append(
                    ViolationItem(
                        category="prompt_injection",
                        rule_name=pat["name"],
                        description=pat["description"],
                        severity=severity,
                        matched_text=matched_snippet,
                        score=item_score,
                    )
                )

        # Composite risk calculation
        composite_score = min(1.0, max_score * self.risk_weight if violations else 0.0)
        has_violations = len(violations) > 0
        should_block = (self.action == "BLOCK" and max_score >= self.block_threshold) or (composite_score >= self.block_threshold)
        suggested_action = "BLOCK" if should_block else ("FLAG" if has_violations else "ALLOW")

        return InspectionResult(
            inspector_name="prompt_injection",
            passed=not should_block,
            risk_score=composite_score,
            action_suggested=suggested_action,
            violations=violations,
            sanitized_text=text,
            metadata={"max_pattern_score": max_score, "matches_count": len(violations)},
        )
