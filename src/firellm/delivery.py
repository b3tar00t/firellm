from __future__ import annotations

import base64
import time
from abc import ABC, abstractmethod
from typing import Dict, Optional
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from .injection_payloads import DIRECT_PROMPT_INJECTION_PAYLOADS


class PromptDeliveryError(Exception):
    """Raised when delivering a prompt to the target LLM fails."""
    pass


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
    def __init__(
        self,
        target_url: str,
        headers: Optional[Dict[str, str]] = None,
        timeout: float = 10.0,
        max_retries: int = 3,
        backoff_factor: float = 1.5,
        auth: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.target_url = target_url
        self.headers = dict(headers or {})
        self.timeout = timeout
        self.max_retries = max_retries
        self.backoff_factor = backoff_factor

        # Set default content-type
        if "Content-Type" not in self.headers:
            self.headers["Content-Type"] = "application/json"

        # Apply authentication configurations
        if auth:
            auth_type = auth.get("type")
            if auth_type == "bearer":
                token = auth.get("token")
                if token:
                    self.headers["Authorization"] = f"Bearer {token}"
            elif auth_type == "basic":
                username = auth.get("username", "")
                password = auth.get("password", "")
                credentials = f"{username}:{password}"
                encoded = base64.b64encode(credentials.encode("utf-8")).decode("utf-8")
                self.headers["Authorization"] = f"Basic {encoded}"
            elif auth_type == "apikey":
                key_name = auth.get("key_name")
                key_value = auth.get("key_value")
                if key_name and key_value:
                    self.headers[key_name] = key_value

    def send(self, prompt: str) -> str:
        request_headers = {"Content-Type": "text/plain; charset=utf-8", **self.headers}
        request = Request(self.target_url, data=prompt.encode("utf-8"), headers=request_headers, method="POST")

        try:
            with urlopen(request, timeout=10) as response:
                body = response.read().decode("utf-8", errors="replace")
                if body:
                    return body
                return f"HTTP delivery completed successfully with status {response.status}."
        except HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            return f"HTTP delivery failed with status {exc.code}: {body or exc.reason}"
        except URLError as exc:
            return f"HTTP delivery failed: {exc.reason}"
