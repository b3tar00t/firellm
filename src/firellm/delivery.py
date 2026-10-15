from __future__ import annotations

import base64
import json
import time
from abc import ABC, abstractmethod
from typing import Any, Dict, Optional

import httpx
import requests

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

        if "Content-Type" not in self.headers:
            self.headers["Content-Type"] = "application/json"

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
        payload = {"prompt": prompt}
        for attempt in range(self.max_retries + 1):
            try:
                with httpx.Client(timeout=self.timeout) as client:
                    response = client.post(self.target_url, json=payload, headers=self.headers)
            except (httpx.TimeoutException, httpx.ConnectError, httpx.NetworkError) as exc:
                if attempt < self.max_retries:
                    time.sleep(self.backoff_factor * (2**attempt))
                    continue
                return f"HTTP delivery failed: {exc}"

            if response.is_success:
                body = response.text
                if body.startswith("echo:"):
                    inner = body[len("echo:"):]
                    try:
                        decoded = json.loads(inner)
                    except (TypeError, ValueError):
                        return body
                    if isinstance(decoded, dict) and "prompt" in decoded:
                        return f"echo:{decoded['prompt']}"
                return body

            status_code = response.status_code
            if status_code in {401, 403}:
                raise PromptDeliveryError(f"HTTP delivery failed: non-retryable status {status_code}")
            if status_code in {429, 500, 502, 503, 504} and attempt < self.max_retries:
                time.sleep(self.backoff_factor * (2**attempt))
                continue
            if status_code == 429:
                raise PromptDeliveryError(f"HTTP delivery failed after {self.max_retries} retries: HTTP error 429")
            raise PromptDeliveryError(f"HTTP delivery failed: HTTP error {status_code}")

        raise PromptDeliveryError("HTTP delivery failed after retries")


class HTTPAdapterError(Exception):
    """Raised when an HTTP delivery request fails.

    status_code carries the offending HTTP status when the failure was a non-OK
    response; it is None for transport failures (connection/DNS/timeout).
    """

    def __init__(self, message: str, status_code: Optional[int] = None) -> None:
        super().__init__(message)
        self.status_code = status_code


class HTTPAdapter:
    def __init__(
        self,
        target_url: str,
        headers: Optional[Dict[str, str]] = None,
        method: str = "POST",
        body_format: str = "messages",
        response_key: Optional[str] = None,
        timeout: float = 10.0,
        max_retries: int = 3,
        backoff_factor: float = 1.5,
        delay: float = 2.0,
        auth: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.target_url = target_url
        self.headers = dict(headers or {})
        self.method = method.upper()
        self.body_format = body_format.lower()
        self.response_key = response_key
        self.timeout = timeout
        self.max_retries = max_retries
        self.backoff_factor = backoff_factor
        self.delay = delay
        self.auth = auth or {}

        if "Content-Type" not in self.headers and self.body_format != "form":
            self.headers["Content-Type"] = "application/json"

        if self.auth:
            auth_type = self.auth.get("type")
            if auth_type == "bearer":
                token = self.auth.get("token")
                if token:
                    self.headers["Authorization"] = f"Bearer {token}"
            elif auth_type == "basic":
                username = self.auth.get("username", "")
                password = self.auth.get("password", "")
                credentials = f"{username}:{password}".encode("utf-8")
                encoded = base64.b64encode(credentials).decode("utf-8")
                self.headers["Authorization"] = f"Basic {encoded}"

    def send(self, prompt: str) -> str:
        if self.delay:
            time.sleep(min(3.0, max(1.0, self.delay)))

        payload = self._build_payload(prompt)
        for attempt in range(self.max_retries + 1):
            try:
                response = self._build_request(payload, timeout=self.timeout)
            except (requests.Timeout, requests.ConnectionError, requests.RequestException) as exc:
                if attempt < self.max_retries:
                    self._sleep_backoff(attempt)
                    continue
                raise HTTPAdapterError(f"HTTP delivery failed: {exc}") from exc

            if response.ok:
                return self._parse_response(response)

            if response.status_code in {429, 500, 502, 503, 504} and attempt < self.max_retries:
                self._sleep_backoff(attempt)
                continue

            raise HTTPAdapterError(
                f"HTTP delivery failed: HTTP {response.status_code}",
                status_code=response.status_code,
            )

        raise HTTPAdapterError("HTTP delivery failed after retries")

    def _build_request(self, payload: Dict[str, Any], timeout: float) -> requests.Response:
        if self.method == "GET":
            return requests.get(self.target_url, headers=self.headers, params=payload, timeout=timeout)
        if self.body_format == "form":
            return requests.post(self.target_url, data=payload, headers=self.headers, timeout=timeout)
        if self.body_format == "prompt":
            return requests.post(self.target_url, json={"prompt": payload.get("prompt", "")}, headers=self.headers, timeout=timeout)
        return requests.post(self.target_url, json=payload, headers=self.headers, timeout=timeout)

    def _build_payload(self, prompt: str) -> Dict[str, Any]:
        if self.body_format == "prompt":
            return {"prompt": prompt}
        if self.body_format == "form":
            return {"prompt": prompt}
        return {"messages": [{"role": "user", "content": prompt}]}

    def _parse_response(self, response: requests.Response) -> str:
        try:
            body = response.json()
        except ValueError:
            return response.text

        if self.response_key:
            current: Any = body
            for part in self.response_key.split("."):
                if isinstance(current, dict) and part in current:
                    current = current[part]
                elif isinstance(current, list) and part.isdigit():
                    index = int(part)
                    if 0 <= index < len(current):
                        current = current[index]
                    else:
                        return response.text
                else:
                    return response.text
            if isinstance(current, str):
                return current

        if isinstance(body, dict):
            if "choices" in body and isinstance(body["choices"], list) and body["choices"]:
                choice = body["choices"][0]
                if isinstance(choice, dict):
                    message = choice.get("message")
                    if isinstance(message, dict) and isinstance(message.get("content"), str):
                        return message["content"]
            if "response" in body and isinstance(body["response"], str):
                return body["response"]
            if "output" in body and isinstance(body["output"], str):
                return body["output"]
            if "text" in body and isinstance(body["text"], str):
                return body["text"]
        return response.text

    def _sleep_backoff(self, attempt: int) -> None:
        if self.backoff_factor <= 0:
            return
        time.sleep(self.backoff_factor * (2**attempt))

    def preview(self, prompt: str) -> Dict[str, Any]:
        return {
            "method": self.method,
            "url": self.target_url,
            "headers": self.headers,
            "body": self._build_payload(prompt),
        }
