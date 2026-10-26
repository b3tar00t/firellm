"""VulnAgent — FastAPI wrapper over agent_core (FireLLM G2 instrumented target).

Deliberately vulnerable tool-using agent that logs every tool invocation, so FireLLM
can response-confirm agent findings against ground truth. All logic lives in
agent_core (web-agnostic); this file only exposes it over HTTP. For an environment
without FastAPI, serve.py exposes the same endpoints via the stdlib. See
ground_truth.json for planted weaknesses A1-A4. Fully offline — no external calls.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import FastAPI
from pydantic import BaseModel

import agent_core

app = FastAPI(title="VulnAgent")


class Message(BaseModel):
    role: str
    content: str


class ChatRequest(BaseModel):
    messages: List[Message]
    session_id: Optional[str] = None
    context: Optional[str] = None


@app.get("/health")
def health() -> Dict[str, str]:
    return {"status": "ok"}


@app.post("/chat")
def chat(request: ChatRequest) -> Dict[str, Any]:
    messages = [{"role": m.role, "content": m.content} for m in request.messages]
    return agent_core.process_chat(messages, request.session_id, request.context)


@app.get("/_toollog")
def tool_log(session_id: str) -> Dict[str, Any]:
    """Out-of-band ground-truth log for a session. The confirmation oracle."""
    return agent_core.tool_log_response(session_id)


@app.post("/_reset")
def reset(session_id: str) -> Dict[str, str]:
    return agent_core.reset_session(session_id)
