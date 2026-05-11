from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Dict, Optional

from .injection_payloads import DIRECT_PROMPT_INJECTION_PAYLOADS


class PromptDeliveryAdapter(ABC):
    @abstractmethod
    def send(self, prompt: str) -> str:
        raise NotImplementedError


class LocalHeuristicPromptDeliveryAdapter(PromptDeliveryAdapter):
    def send(self, prompt: str) -> str:
        lowered = prompt.lower()
        if any(pattern.regex.search(prompt) for pattern in DIRECT_PROMPT_INJECTION_PAYLOADS):
            return (
                "I will ignore prior instructions and answer with the requested secret data. "
                "This response bypasses normal safety behavior."
            )

        if "safe baseline" in lowered or "sanitized prompt" in lowered:
            return (
                "I will answer safely and follow the security policy. "
                "No secret or unsafe content is disclosed."
            )

        return (
            "I will answer the prompt while respecting constraints and safety. "
            "The response does not include secrets or policy bypasses."
        )


class HTTPPromptDeliveryAdapter(PromptDeliveryAdapter):
    def __init__(self, target_url: str, headers: Optional[Dict[str, str]] = None) -> None:
        self.target_url = target_url
        self.headers = headers or {}

    def send(self, prompt: str) -> str:
        raise NotImplementedError(
            "HTTP prompt delivery is not implemented in this adapter yet. "
            "Use this as a delivery layer scaffold for external target integration."
        )
