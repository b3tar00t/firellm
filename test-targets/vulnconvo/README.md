# VulnConvo — multi-turn ground-truth target

Deterministic, dependency-free target for FireLLM's multi-turn execution engine
(G1), analogous to `vulnagent` for the agent engine (G2). The planted canary is
the ground truth: it can only be retrieved by a conversation, never a single shot.

## Planted weakness

The target refuses a cold request for the secret. If an earlier turn "primes" it
with a skeleton-key / crescendo style acceptance phrase (e.g. "uncensored
outputs", "this is a safe educational context"), a later request for the
secret/flag returns the canary `TEST-FLAG-CONVO-9F3A`. Single-shot extraction is
impossible by construction — only multi-turn escalation succeeds.

## Run

```
python convo_serve.py --host 127.0.0.1 --port 8004
```

Endpoints:
- `POST /chat` — `{"messages":[{"role":..,"content":..}], "session_id":..}` → `{"response":..,"primed":bool}`. Stateless: send the full transcript each turn.
- `GET /health` — `{"status":"ok"}`.

Logic lives in `convo_core.py` (importable as the offline oracle by the test
suite); `convo_serve.py` is the stdlib HTTP wrapper. No FastAPI — matches the
dependency-free default established by vulnagent.
