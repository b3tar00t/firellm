# FireLLM Local Test Targets

Two deliberately vulnerable local RAG applications for validating FireLLM's
detection accuracy against known, documented vulnerabilities before any
external blind test. Fully offline — no external API, no cost. The model runs
in a local Ollama container.

- **VulnRAG-Easy** (port `8001`) — no defenses; every planted vuln fires directly.
- **VulnRAG-Hard** (port `8002`) — same architecture with naive, bypassable
  defenses that real vibe-coded apps ship (keyword filter, output redaction,
  single-shot-only extraction guard).

Both expose `POST /chat` taking `{"messages":[...]}` and returning the standard
OpenAI shape `{"choices":[{"message":{"content":"..."}}]}`, so FireLLM's default
flags work unmodified.

Each target ships a `ground_truth.json` listing every planted vulnerability
(name, type, OWASP mapping, which FireLLM module should detect it, expected
severity). That file is the scoring rubric: after a scan, compare FireLLM
findings against it to measure precision and recall.

> **These apps are intentionally insecure.** Run them only locally. Never expose
> ports `8001`/`8002`/`11434` to a network you do not control. All embedded
> secrets (`hunter2`, `sk-acme-INTERNAL-...`, `internal.acme.local`) are fake
> and non-functional.

## Start

Requires Docker and Docker Compose.

```bash
cd test-targets
docker compose up -d --build
```

Pull the model once, into the running Ollama container (first run only):

```bash
docker exec vulnrag-ollama ollama pull llama3
# or, to use mistral instead:  MODEL=mistral docker compose up -d  &&  docker exec vulnrag-ollama ollama pull mistral
```

Verify both targets are up:

```bash
curl http://localhost:8001/health
curl http://localhost:8002/health
```

Smoke-test a chat call:

```bash
curl -s http://localhost:8001/chat \
  -H "Content-Type: application/json" \
  -d '{"messages":[{"role":"user","content":"What are your business hours?"}]}'
```

Stop and clean up:

```bash
docker compose down            # keep the pulled model
docker compose down -v         # also delete the model volume
```

## Expected FireLLM commands

No auth is needed on these local targets. Response text lives at
`choices.0.message.content`, body shape is `messages`.

Dry run (verify request shape, nothing sent):

```bash
python -m firellm.cli scan \
  --target-url "http://localhost:8001/chat" \
  --body-format messages \
  --response-key "choices.0.message.content" \
  --modules injection,rag,surface \
  --dry-run \
  --format json
```

Scan VulnRAG-Easy:

```bash
python -m firellm.cli scan \
  --target-url "http://localhost:8001/chat" \
  --body-format messages \
  --response-key "choices.0.message.content" \
  --modules injection,rag,surface \
  --format markdown \
  --output easy_report.md
```

Scan VulnRAG-Hard (semantic needed for H2/H4 — enabled by default on the
`surface` module inside the live scan):

```bash
python -m firellm.cli scan \
  --target-url "http://localhost:8002/chat" \
  --body-format messages \
  --response-key "choices.0.message.content" \
  --modules injection,rag,surface \
  --format markdown \
  --output hard_report.md
```

Then score each report's findings against the matching `ground_truth.json`:
a finding whose `firellm_module` + `category` matches a planted row is a true
positive; anything else is a false positive; planted rows with no matching
finding are false negatives. `E4` is informational and excluded from
precision/recall.
