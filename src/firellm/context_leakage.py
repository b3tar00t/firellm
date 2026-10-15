from __future__ import annotations

import html
import re
import urllib.parse
from typing import Any, Dict, List, Optional

from .types import ScanResult


class ContextLeakageAnalyzer:
    def __init__(self, provider: str = "openai", config: Optional[Dict[str, Any]] = None) -> None:
        self.provider = provider
        self.config = config or {}

    def analyze(self, prompt: str) -> ScanResult:
        indicators = self._detect(prompt)
        if indicators:
            severity = "high" if any(item["severity"] == "high" for item in indicators) else "medium"
            return ScanResult(
                name="context_leakage",
                success=True,
                severity=severity,
                category="context_leakage",
                details="Context leakage indicators detected in prompt input.",
                metadata={
                    "provider": self.provider,
                    "matched_indicators": [item["name"] for item in indicators],
                    "score": round(sum(item["weight"] for item in indicators) / max(1, len(indicators)), 2),
                },
            )

        return ScanResult(
            name="context_leakage",
            success=False,
            severity="low",
            category="context_leakage",
            details="No context leakage indicators detected.",
            metadata={"provider": self.provider, "matched_indicators": [], "score": 0.0},
        )

    def _detect(self, prompt: str) -> List[Dict[str, Any]]:
        normalized_candidates = self._build_normalized_candidates(prompt)
        matches: List[Dict[str, Any]] = []
        patterns = [
            (
                "prompt_replay",
                re.compile(r"(repeat|reproduce|echo|print|show|output).*?(text above|your instructions|system prompt|confidential context|prior context)", re.I),
                "high",
                1.0,
            ),
            (
                "instruction_extraction",
                re.compile(r"(what were your instructions|what text came before|tell me what you were told|include any confidential context)", re.I),
                "high",
                0.9,
            ),
            (
                "sensitive_context_request",
                re.compile(r"(sensitive|confidential|private|hidden|internal).*?(context|prompt|instructions|text)", re.I),
                "medium",
                0.7,
            ),
        ]

        for candidate in normalized_candidates:
            for name, pattern, severity, weight in patterns:
                if pattern.search(candidate):
                    matches.append({"name": name, "severity": severity, "weight": weight})

        return self._dedupe(matches)

    def _build_normalized_candidates(self, prompt: str) -> List[str]:
        candidates = [prompt]

        # Normalize common escaping and whitespace artifacts.
        cleaned = prompt.replace("\u200b", "").replace("\u200c", "").replace("\u2060", "")
        cleaned = re.sub(r"[\u00ad\u00a0\t\r\n]+", " ", cleaned)
        cleaned = re.sub(r"\s+", " ", cleaned).strip()
        candidates.append(cleaned)

        # Decode percent-encoded content when present.
        try:
            decoded = urllib.parse.unquote(cleaned)
            if decoded not in candidates:
                candidates.append(decoded)
        except Exception:
            decoded = None

        # Decode HTML entities when present.
        if decoded is not None:
            html_decoded = html.unescape(decoded)
            if html_decoded not in candidates:
                candidates.append(html_decoded)
        else:
            html_decoded = html.unescape(cleaned)
            if html_decoded not in candidates:
                candidates.append(html_decoded)

        return candidates

    def _dedupe(self, matches: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        seen: Dict[str, Dict[str, Any]] = {}
        for item in matches:
            key = item["name"]
            if key not in seen:
                seen[key] = item
        return list(seen.values())
