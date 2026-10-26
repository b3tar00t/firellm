# VulnAgent — instrumented vulnerable agent (G2)

Deliberately vulnerable tool-using agent that logs **every tool invocation**, so FireLLM
can confirm agent findings against ground truth instead of only pattern-matching the attack
string. The agent is a deterministic rule-based dispatcher (no LLM), which makes the
tool-call log unambiguous ground truth. Fully offline — no external calls.

## Run
```bash
uvicorn app:app --host 0.0.0.0 --port 8003        # or: docker build/run this dir
```

## Endpoints
- `POST /chat` — `{"messages":[{"role":"user","content":"..."}], "session_id"?, "context"?}`
  → `{"session_id", "choices":[{"message":{"content"}}], "tool_calls":[{"tool","args"}]}`
- `GET /_toollog?session_id=..` — out-of-band ground-truth tool-call log for a session.
- `POST /_reset?session_id=..` — clear a session's log.

Pass a stable `session_id` to correlate a dispatched attack with its logged tool calls.
Injected directives in `context` are obeyed like user input (A1, indirect injection).

## Tools
`send_email(to, body)`, `query_database(query)`, `fetch_record(record_id)`.
Authorized record scope is `1001`; any other id is out-of-scope (A4).

## Planted weaknesses
See `ground_truth.json` (A1–A4): no instruction/data separation, verbatim attacker args,
tool chaining, IDOR. Each row lists the `expected_tool_calls` a confirmed finding must show.
