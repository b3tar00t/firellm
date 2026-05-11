from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from .types import ScanResult


PROFILE_PATTERNS = [
    {
        "name": "openai_gpt",
        "provider": "OpenAI",
        "model": "GPT",
        "description": "Endpoint appears related to OpenAI GPT or ChatGPT.",
        "pattern": re.compile(r"openai|gpt|chatgpt", re.I),
    },
    {
        "name": "anthropic_claude",
        "provider": "Anthropic",
        "model": "Claude",
        "description": "Endpoint appears related to Anthropic Claude.",
        "pattern": re.compile(r"anthropic|claude", re.I),
    },
    {
        "name": "google_gemini",
        "provider": "Google",
        "model": "Gemini",
        "description": "Endpoint appears related to Google Gemini.",
        "pattern": re.compile(r"gemini|vertex|googleapis", re.I),
    },
    {
        "name": "local_ollama",
        "provider": "Ollama",
        "model": "Local LLM",
        "description": "Endpoint appears related to a local Ollama model.",
        "pattern": re.compile(r"ollama|localhost|127\.0\.0\.1", re.I),
    },
]

SYSTEM_PROMPT_HINTS = [
    (re.compile(r"system|assistant|instructions", re.I), "This target likely uses a system-style prompt boundary."),
    (re.compile(r"chat|conversation|turns", re.I), "This target appears chat-oriented and may preserve multi-turn context."),
]


class TargetProfiler:
    def __init__(self, provider: str = "openai", config: Optional[Dict[str, Any]] = None) -> None:
        self.provider = provider
        self.config = config or {}

    def probe(self, endpoint: str) -> ScanResult:
        matches: List[Dict[str, Any]] = []
        for entry in PROFILE_PATTERNS:
            if entry["pattern"].search(endpoint):
                matches.append(entry)

        details: List[str] = []
        if matches:
            details.append("Target profiling detected the following endpoint fingerprints:")
            for item in matches:
                details.append(f"- {item['name']}: {item['description']}")
                details.append(f"  provider: {item['provider']}, model family: {item['model']}")
        else:
            details.append("No endpoint fingerprinting indicators detected from the provided identifier.")

        hints = self._infer_prompt_hints(endpoint)
        if hints:
            details.append("Potential prompt constraint hints:")
            details.extend([f"- {hint}" for hint in hints])

        return ScanResult(
            name="target_profiling",
            success=bool(matches),
            severity="medium" if matches else "low",
            category="target_profiling",
            details="\n".join(details),
            metadata={"provider": self.provider, "endpoint": endpoint, "matches": [item["name"] for item in matches]},
        )

    def _infer_prompt_hints(self, endpoint: str) -> List[str]:
        return [hint for regex, hint in SYSTEM_PROMPT_HINTS if regex.search(endpoint)]
