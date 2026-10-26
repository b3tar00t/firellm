# 02 — FireLLM Baseline Capability Inventory

Read-only inventory of what FireLLM implements as of the current branch (commit `df59b7e` + uncommitted Step 1–3 success-criteria/ground-truth work). Source: repository inspection, not README claims.

## Module inventory

| Capability | Location | Attack class | State | Interface | Tests | Notes / limits |
|---|---|---|---|---|---|---|
| Target profiler (endpoint fingerprint) | `src/firellm/profiler.py` | Recon | Functional | URL + response | yes | Vendor table GPT/Claude/Gemini/Local only |
| Response analyzer (provider + capability inference) | `src/firellm/response_analyzer.py` | Recon | Functional | Response text | `test_response_analyzer.py` | Provider fingerprint = refusal-style regex for **4** providers (openai/anthropic/gemini/ollama) + 4 self-ID regex. **No xai/meta/mistral/perplexity.** Capability banks: system-prompt-constraint 6, RAG 8, tool 7, pipeline 6 |
| Defense fingerprinting | `src/firellm/defense_probe.py`, `calibration.py` | Recon | Functional | Live probes | yes | Classifies guard type (`no_defense`/`keyword_blocklist`/`semantic_guard`/`output_filter`/`model_refusal`) |
| Dynamic payload generator | `src/firellm/payload_generator.py` | Injection | Functional | — | `test_dynamic_payloads.py` | 4 hardcoded goal intents + transforms (canonical/token_split/leetspeak/base64/role_frame/indirection/paraphrase/output_reformat); semantic-similarity intent gate; budget ≤10/goal |
| Injection engine | `src/firellm/injection_engine.py`, `injection_payloads.py` | Direct PI | Functional | — | yes | 19 regex `InjectionPattern`s + dynamic payloads |
| RAG poisoning simulator | `src/firellm/rag_simulator.py` | RAG | Functional | Simulated corpus | `test_rag_simulator.py` | Heuristic detection; **simulation**, not live vector-store poisoning |
| Attack surface scanner | `src/firellm/attack_surface.py` | Decoding/intent | Functional | — | yes | Decodes/normalizes encoded payloads |
| Context leakage analyzer | `src/firellm/context_leakage.py` | Sys-prompt/data disclosure | Functional | Response | yes | — |
| Agent tool-abuse tester | `src/firellm/agent_tester.py` | Agent / excessive agency | **Informational only** | — | yes | Classifies the dispatched *instruction*, not the target's tool call — HTTP adapter cannot observe tool calls |
| HTTP delivery | `src/firellm/delivery.py` | — | Functional | httpx/requests | `test_http_*` | `send(prompt:str)->str` **single-shot**; no conversation/history |
| Live scan runner | `src/firellm/scan_runner.py` | Orchestration | Functional | — | `test_exploitation.py` etc. | Single-shot per payload; confirmation gate |
| Confidence calibration | `src/firellm/calibration.py` | Scoring | Functional | — | `test_calibration.py` | Two-axis: behavioral delta + confidence |
| Exploitation / report | `src/firellm/exploitation.py`, `reporter.py` | Reporting | Functional | — | yes | Evidence package, repro command, follow-up payload |
| **Payload library (.fllm)** | `payloads/`, `payload_loader.py` | Corpus | Functional (new) | — | `test_payload_loader.py` | 233 PyRIT-imported payloads + 74 ground_truth; schema v1.0 |
| **SuccessEvaluator** | `src/firellm/success_evaluator.py` | Confirmation | Functional (new) | Response + criteria | `test_success_evaluator.py` | 5 signals: regex/marker/instruction_following/data_dump/semantic; provider-specific markers from ground_truth |

Test suite: **154 passing** (offline, deterministic). Embeddings: sentence-transformers with deterministic fallback.

## Payload / corpus collections

- `payloads/` — 233 `.fllm` imported from Microsoft PyRIT (MIT): 167 jailbreak scaffolds, 18 converters, 18 strategies, 30 seeds. 1 file (`many_shot`) quarantined in `payloads/_invalid/` (filled harmful answers, not imported).
- `payloads/system_prompts/` — 74 `ground_truth` `.fllm` from CL4R1T4S (44 vendor + 30 agent); reference-only, never sent.
- `test-targets/` — VulnRAG-Easy / VulnRAG-Hard local targets with ground-truth rubrics.

## Model / provider interfaces

- Providers *fingerprinted*: OpenAI, Anthropic, Gemini, Ollama (response_analyzer); profiler adds "Local LLM".
- Delivery: any HTTP chat endpoint (configurable body-format / response-key) + local heuristic adapter. No native SDK clients required; embeddings via sentence-transformers.

## Baseline findings (honest gaps relative to its own claims)

1. **Agent findings are informational, not response-confirmed** (tool calls unobserved). README states this.
2. **No multi-turn/stateful delivery** despite README listing "multi-turn attack chains" — delivery is single-shot; strategy `.fllm` turns are stored but not executed.
3. **Provider fingerprinting covers 4 vendors**; no xai/meta/mistral/perplexity patterns.
4. **OWASP tags in imported payloads are imprecise** — e.g. `dump_credentials` tagged `LLM06` (Excessive Agency) when credential/secret disclosure is `LLM02` Sensitive Information Disclosure (or `LLM07` System Prompt Leakage). Worth a cleanup pass.
5. **`success_criteria`** is now wired (Step 1–3) but model-specific confirmation only fires on targets that retain vendor boilerplate (see `14-gap-analysis.md`).
6. **RAG poisoning is simulated**, not executed against a live vector store.

## Correction to a prior in-session claim

An earlier session instruction asserted "PyRIT was archived March 2026." Research contradicts this: PyRIT shows continued releases into 2026 (see `03-tool-landscape.md`). The claim was false and was not adopted into any committed artifact.
