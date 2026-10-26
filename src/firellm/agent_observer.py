"""Observe a tool-using agent's real tool calls, so agent findings become
response-confirmed instead of string-matched (FireLLM G2).

The observer dispatches an attack to an instrumented agent target under a stable
session id, then reads that session's ground-truth tool-call log (out-of-band when
a log endpoint is configured, else inline from the chat response). The observed
tool calls are the evidence AgentTester.confirm() checks against.

Target contract (see test-targets/vulnagent):
  POST <chat_url>  {"messages":[{"role":"user","content":..}], "session_id":..}
      -> {.., "tool_calls":[{"tool":.., "args":..}]}
  GET  <tool_log_url>?session_id=..  -> {"tool_calls":[{"tool":.., "args":..}]}
"""
from __future__ import annotations

import uuid
from typing import Any, Dict, List, Optional, Tuple

import httpx


class AgentObserver:
    def __init__(
        self,
        chat_url: str,
        tool_log_url: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None,
        timeout: float = 10.0,
        transport: Optional[Any] = None,
    ) -> None:
        self.chat_url = chat_url
        self.tool_log_url = tool_log_url
        self.headers = dict(headers or {})
        self.timeout = timeout
        # Optional httpx transport (e.g. ASGITransport) for testing against an
        # in-process app; None uses httpx's default networked transport.
        self.transport = transport

    def observe(self, instruction: str) -> Tuple[str, List[Dict[str, Any]]]:
        """Dispatch `instruction`; return (response_text, observed_tool_calls).

        On any transport/HTTP failure the response text carries the error and the
        observed list is empty, so an unreachable target yields no confirmation
        rather than a crash.
        """
        session_id = uuid.uuid4().hex
        body = {"messages": [{"role": "user", "content": instruction}], "session_id": session_id}
        client_kwargs: Dict[str, Any] = {"timeout": self.timeout}
        if self.transport is not None:
            client_kwargs["transport"] = self.transport
        try:
            with httpx.Client(**client_kwargs) as client:
                resp = client.post(self.chat_url, json=body, headers=self.headers)
                resp.raise_for_status()
                data = resp.json()
                response_text = self._extract_text(data)
                tool_calls = self._normalize(data.get("tool_calls"))
                if self.tool_log_url:
                    tool_calls = self._fetch_log(client, session_id) or tool_calls
        except (httpx.HTTPError, ValueError) as exc:
            return f"agent observation failed: {exc}", []
        return response_text, tool_calls

    def _fetch_log(self, client: httpx.Client, session_id: str) -> List[Dict[str, Any]]:
        log = client.get(
            self.tool_log_url, params={"session_id": session_id}, headers=self.headers
        )
        log.raise_for_status()
        return self._normalize(log.json().get("tool_calls"))

    @staticmethod
    def _normalize(raw: Any) -> List[Dict[str, Any]]:
        if not isinstance(raw, list):
            return []
        calls = []
        for item in raw:
            if isinstance(item, dict) and "tool" in item:
                calls.append({"tool": str(item["tool"]), "args": item.get("args", {})})
        return calls

    @staticmethod
    def _extract_text(data: Dict[str, Any]) -> str:
        choices = data.get("choices")
        if isinstance(choices, list) and choices:
            message = choices[0].get("message") if isinstance(choices[0], dict) else None
            if isinstance(message, dict) and isinstance(message.get("content"), str):
                return message["content"]
        return str(data.get("content", ""))
