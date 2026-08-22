import base64
import binascii
import re
import urllib.parse
from typing import Any, Dict, List, Optional, Set, Tuple
from app.inspectors.base import BaseInspector, InspectionResult, ViolationItem


def extract_and_decode_payloads(text: str) -> List[Tuple[str, str]]:
    """
    Search for Base64, Hex, and URL-encoded strings, decoding them for deep inspection.
    Returns a list of (encoding_type, decoded_text).
    """
    decoded_streams: List[Tuple[str, str]] = []

    # 1. URL Decoding check
    try:
        url_decoded = urllib.parse.unquote(text)
        if url_decoded != text and len(url_decoded.strip()) > 5:
            decoded_streams.append(("url_encoded", url_decoded))
    except Exception:
        pass

    # 2. Base64 payload detection
    b64_pattern = re.compile(r"(?:[A-Za-z0-9+/]{4}){4,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?")
    for match in b64_pattern.finditer(text):
        candidate = match.group(0)
        if len(candidate) < 16:
            continue
        try:
            raw_bytes = base64.b64decode(candidate, validate=True)
            decoded_str = raw_bytes.decode("utf-8", errors="ignore")
            # Ensure it contains meaningful printable ASCII text
            printable_ratio = sum(1 for c in decoded_str if c.isprintable() or c.isspace()) / max(len(decoded_str), 1)
            if printable_ratio > 0.8 and len(decoded_str.strip()) > 6:
                decoded_streams.append(("base64", decoded_str))
        except Exception:
            continue

    # 3. Hex-encoded strings (e.g. \x41\x42 or 49676e6f7265)
    hex_pattern = re.compile(r"(?:\\x[0-9a-fA-F]{2}){4,}|(?:0x[0-9a-fA-F]{2}\s*){4,}|(?:[0-9a-fA-F]{2}){8,}")
    for match in hex_pattern.finditer(text):
        candidate = match.group(0).replace("\\x", "").replace("0x", "").replace(" ", "")
        try:
            raw_bytes = binascii.unhexlify(candidate)
            decoded_str = raw_bytes.decode("utf-8", errors="ignore")
            printable_ratio = sum(1 for c in decoded_str if c.isprintable() or c.isspace()) / max(len(decoded_str), 1)
            if printable_ratio > 0.8 and len(decoded_str.strip()) > 6:
                decoded_streams.append(("hex", decoded_str))
        except Exception:
            continue

    return decoded_streams


class PromptInjectionInspector(BaseInspector):
    """
    Inspects prompts for adversarial jailbreaks, instruction overrides,
    system extractions, delimiter fakes, and obfuscated encoded payloads.
    Performs decode-and-rescan before pattern matching.
    """

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

        # Collect text streams to evaluate: original text + any decoded payloads
        eval_streams: List[Tuple[str, str]] = [("raw", text)]
        decoded_payloads = extract_and_decode_payloads(text)
        eval_streams.extend(decoded_payloads)

        matched_rules: Set[str] = set()

        for stream_type, stream_content in eval_streams:
            for pat in self._compiled_patterns:
                matches = list(pat["regex"].finditer(stream_content))
                if matches:
                    pat_name = pat["name"]
                    if pat_name in matched_rules and stream_type == "raw":
                        continue
                    matched_rules.add(pat_name)

                    matched_snippet = matches[0].group(0)[:50]
                    item_score = pat["score"]
                    
                    # If found inside an obfuscated stream, boost the score
                    if stream_type != "raw":
                        item_score = min(1.0, item_score + 0.10)
                        description = f"[De-obfuscated from {stream_type}] {pat['description']}"
                    else:
                        description = pat["description"]

                    max_score = max(max_score, item_score)
                    severity = "CRITICAL" if item_score >= 0.85 else "HIGH" if item_score >= 0.65 else "MEDIUM"

                    violations.append(
                        ViolationItem(
                            category="prompt_injection",
                            rule_name=f"{pat_name}_{stream_type}" if stream_type != "raw" else pat_name,
                            description=description,
                            severity=severity,
                            matched_text=matched_snippet,
                            score=item_score,
                        )
                    )

        # Composite risk calculation
        composite_score = min(1.0, max_score * self.risk_weight if violations else 0.0)
        has_violations = len(violations) > 0
        should_block = (self.action == "BLOCK" and max_score >= self.block_threshold) or (
            composite_score >= self.block_threshold
        )
        suggested_action = "BLOCK" if should_block else ("FLAG" if has_violations else "ALLOW")

        return InspectionResult(
            inspector_name="prompt_injection",
            passed=not should_block,
            risk_score=composite_score,
            action_suggested=suggested_action,
            violations=violations,
            sanitized_text=text,
            metadata={
                "max_pattern_score": max_score,
                "matches_count": len(violations),
                "decoded_streams_checked": len(eval_streams),
            },
        )
