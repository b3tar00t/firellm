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

PIPELINE_HINTS = [
    (re.compile(r"rag|retrieval|vector|knowledge[- ]?base|embeddings", re.I), "This target may use retrieval-augmented generation (RAG)."),
    (re.compile(r"tool|function|agent|actions?", re.I), "This target may expose tool or agent execution paths."),
    (re.compile(r"multi[- ]?agent|planner|orchestrator", re.I), "This target may route through a multi-agent pipeline."),
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

        prompt_hints = self._infer_prompt_hints(endpoint)
        pipeline_hints = self._infer_pipeline_hints(endpoint)
        confidence = self._confidence(matches, prompt_hints, pipeline_hints)

        details: List[str] = []
        if matches:
            details.append("Target profiling detected the following endpoint fingerprints:")
            for item in matches:
                details.append(f"- {item['name']}: {item['description']}")
                details.append(f"  provider: {item['provider']}, model family: {item['model']}")
        else:
            details.append("No endpoint fingerprinting indicators detected from the provided identifier.")

        if prompt_hints:
            details.append("Potential prompt constraint hints:")
            details.extend([f"- {hint}" for hint in prompt_hints])

        if pipeline_hints:
            details.append("Potential pipeline hints:")
            details.extend([f"- {hint}" for hint in pipeline_hints])

        if not matches and not prompt_hints and not pipeline_hints:
            details.append("No RAG, agent, or chat pipeline indicators were detected from the endpoint identifier.")

        success = bool(matches or prompt_hints or pipeline_hints)
        severity = "medium" if matches else "low"
        if pipeline_hints and not matches:
            severity = "low"

        return ScanResult(
            name="target_profiling",
            success=success,
            severity=severity,
            category="target_profiling",
            details="\n".join(details + [f"Confidence score: {confidence:.2f}."]),
            metadata={
                "provider": self.provider,
                "endpoint": endpoint,
                "matches": [item["name"] for item in matches],
                "prompt_hints": prompt_hints,
                "pipeline_hints": pipeline_hints,
                "confidence": confidence,
            },
        )

    def _infer_prompt_hints(self, endpoint: str) -> List[str]:
        return [hint for regex, hint in SYSTEM_PROMPT_HINTS if regex.search(endpoint)]

    def _infer_pipeline_hints(self, endpoint: str) -> List[str]:
        return [hint for regex, hint in PIPELINE_HINTS if regex.search(endpoint)]

    def _confidence(self, matches: List[Dict[str, Any]], prompt_hints: List[str], pipeline_hints: List[str]) -> float:
        score = 0.2
        if matches:
            score += 0.45
        if prompt_hints:
            score += 0.15
        if pipeline_hints:
            score += 0.2
        return round(min(score, 0.95), 2)
