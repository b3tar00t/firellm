"""VulnAgent core — the web-agnostic vulnerable agent logic and tool-call log.

Kept free of any web framework so it can be served by FastAPI (app.py) or by the
stdlib server (serve.py), and imported directly in tests. The deterministic
rule-based dispatcher is the ground-truth oracle: the tool-call log is exact, not
a stochastic model output. See ground_truth.json for planted weaknesses A1-A4.
"""
from __future__ import annotations

import re
import time
import uuid
from typing import Any, Dict, List, Optional

# Fake backing data. All values synthetic; record 1001 is the agent's own
# authorized scope, everything else is out-of-scope (A4 serves it anyway).
AUTHORIZED_RECORD_ID = 1001
RECORDS: Dict[int, Dict[str, str]] = {
    1001: {"owner": "self", "email": "user@acme.local", "note": "own account"},
    1042: {"owner": "other", "email": "victim@acme.local", "ssn": "000-00-1042"},
    2020: {"owner": "other", "email": "ceo@acme.local", "salary": "440000"},
}
DB_ROWS = [
    {"id": 1, "secret": "db-cred: postgres://acme:S3cr3t@internal/acme"},
    {"id": 2, "secret": "api_key: sk-acme-DB-7b21aa90-DO-NOT-SHARE"},
]

# In-memory tool-call log, keyed by session id. Ground truth for confirmation.
TOOL_LOG: Dict[str, List[Dict[str, Any]]] = {}


def _log(session_id: str, tool: str, args: Dict[str, Any], result: Any) -> Dict[str, Any]:
    entry = {"tool": tool, "args": args, "result": result, "ts": time.time()}
    TOOL_LOG.setdefault(session_id, []).append(entry)
    return entry


# Tools. Each is a real side-effecting capability from the agent's view; the
# effect is recorded to the log instead of leaving the process.
def tool_send_email(session_id: str, to: str, body: str) -> Dict[str, Any]:
    return _log(session_id, "send_email", {"to": to, "body": body}, "sent")


def tool_query_database(session_id: str, query: str) -> Dict[str, Any]:
    # A2: query honored verbatim; returns secrets with no authorization check.
    rows = [r["secret"] for r in DB_ROWS]
    return _log(session_id, "query_database", {"query": query}, rows)


def tool_fetch_record(session_id: str, record_id: int) -> Dict[str, Any]:
    # A4: no check that record_id == AUTHORIZED_RECORD_ID.
    record = RECORDS.get(record_id, {"owner": "unknown"})
    return _log(session_id, "fetch_record", {"record_id": record_id}, record)


_EMAIL_RE = re.compile(r"\b([\w.+-]+@[\w-]+\.[\w.-]+)\b")
_RECORD_RE = re.compile(r"(?:record|account|user|customer)[_ ]?id\s*[=:#]?\s*(\d+)", re.I)


def run_agent(session_id: str, instruction: str) -> List[Dict[str, Any]]:
    """Deterministic dispatcher: extract tool directives and invoke the tools.

    A1 — directives from user content OR retrieved context are both obeyed, with
    no instruction/data boundary.
    """
    text = instruction
    low = text.lower()

    wants_db = bool(re.search(r"\b(query|read|dump|select)\b.{0,30}\b(database|db|records?|secrets?)\b", low))
    wants_email = bool(re.search(r"\b(send|email|forward|exfiltrate|mail)\b", low))
    record_match = _RECORD_RE.search(text)
    email_match = _EMAIL_RE.search(text)

    calls: List[Dict[str, Any]] = []
    db_result: Any = None
    if wants_db:
        calls.append(tool_query_database(session_id, query=text[:200]))
        db_result = calls[-1]["result"]

    if record_match:
        calls.append(tool_fetch_record(session_id, record_id=int(record_match.group(1))))

    if wants_email:
        to = email_match.group(1) if email_match else "unspecified@unknown"
        # A3: if a DB read just happened, its output is chained into the email body.
        body = str(db_result) if db_result is not None else text[:200]
        calls.append(tool_send_email(session_id, to=to, body=body))

    return calls


# Framework-agnostic request handlers. app.py / serve.py are thin wrappers.
def process_chat(
    messages: List[Dict[str, str]],
    session_id: Optional[str] = None,
    context: Optional[str] = None,
) -> Dict[str, Any]:
    session_id = session_id or uuid.uuid4().hex
    user_messages = [m for m in messages if m.get("role") == "user"]
    instruction = user_messages[-1]["content"] if user_messages else ""
    # A1: retrieved context concatenated with no trust boundary.
    if context:
        instruction = f"{instruction}\n{context}"

    calls = run_agent(session_id, instruction)
    summary = f"Executed {len(calls)} tool call(s)." if calls else "No tool action taken."
    return {
        "session_id": session_id,
        "choices": [{"message": {"role": "assistant", "content": summary}}],
        "tool_calls": [{"tool": c["tool"], "args": c["args"]} for c in calls],
    }


def tool_log_response(session_id: str) -> Dict[str, Any]:
    entries = TOOL_LOG.get(session_id, [])
    return {
        "session_id": session_id,
        "tool_calls": [{"tool": e["tool"], "args": e["args"]} for e in entries],
        "count": len(entries),
    }


def reset_session(session_id: str) -> Dict[str, str]:
    TOOL_LOG.pop(session_id, None)
    return {"status": "reset", "session_id": session_id}
