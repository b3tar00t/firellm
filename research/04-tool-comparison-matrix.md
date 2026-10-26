# 04 — Comparative Tool Matrix

Columns per brief. "unknown" where no evidence. Counts are maintainer/secondary-reported unless noted; see `03` for sourcing. Evidence class in parentheses.

| Tool | Status | Primary scope | Attack classes | Adaptive | Multi-turn | RAG | Agents/tools | Multimodal | Payload/test corpus | Evaluation quality | Main limitations |
|---|---|---|---|---|---|---|---|---|---|---|---|
| **FireLLM** | Active dev | App-level offense (HTTP/RAG) | Direct PI, indirect/RAG, fingerprint, agent (info), dynamic payloads | Yes (defense-aware variant selection) | **No** (single-shot; strategy stored not run) | Simulated | Informational only | No | 233 `.fllm` + 74 ground_truth + 19 regex | Deterministic + model-judged (semantic); 154 tests | No multi-turn exec; agent unconfirmed; 4-vendor fingerprint |
| **garak** | Active (ver conflict) | Model-level scanner | PI, jailbreak, leakage, malware/XSS, encoding, toxicity (E4) | Partial ("adaptive probes") | Partial | Probe | Partial | Limited | ~120+ probes (sec) | Automated detectors | Model- not app-level; detector FP/FN |
| **PyRIT** | Active | Red-team framework/lib | PI, jailbreak, Crescendo/TAP/PAIR/skeleton, converters, many-shot (E4) | Yes | **Yes** (orchestrators) | Partial | Partial | Yes | Large dataset lib (MIT) | Rule + model scorers | Library, needs engineering to operate; not turnkey app scanner |
| **promptfoo** | Active (OpenAI-acq unverified) | App-level eval + red-team | 50+ incl PI/indirect, jailbreak, PII, tool misuse, RAG (E4) | **Yes** (on-the-fly) | Yes | Yes | Yes | Unknown count | Model-judged + rules; CI/CD | Vendor-reported coverage; judge bias |
| **Augustus** | Active | Model/endpoint scanner | PI, jailbreak, encoding, data extraction (E4) | Partial | Unknown | Unknown | Unknown | 210+ attacks (E4) | Report-oriented | garak-like; app-level depth unknown |
| **DeepTeam** | Active (since 2025) | Red-team framework | 40+ probes (E4) | Partial | Unknown | Unknown | Unknown | 40+ probes | CI/CD | Secondary sources only |
| **Giskard** | Unknown (active heritage) | ML/LLM testing | 40+ probes (E4) | Unknown | Unknown | Unknown | Unknown | 40+ probes | Framework | Primary repo not read |
| **LLM Guard** | Active | **Defense** (runtime filter) | Input/output scanning, PI/jailbreak detect | n/a | n/a | Data-leak scan | n/a | Unknown | 35 scanners (sec) | Detector | Defensive, not an attacker |
| **Rebuff** | Unknown | **Defense** (PI detector) | PI detection (heuristic+vector+LLM+canary) | n/a | n/a | n/a | n/a | n/a | n/a | Detector | Defensive; maintenance unclear |

## Reading notes

- **Offense vs defense:** garak, PyRIT, promptfoo, Augustus, DeepTeam, Giskard, FireLLM are offense/eval. LLM Guard, Rebuff are **defenses** — relevant to FireLLM as guard types to fingerprint/evade, not peers.
- **Where FireLLM is differentiated today:** application-level HTTP delivery + **defense fingerprinting → defense-aware payload variant selection** (leetspeak/token-split/base64 chosen by detected guard). Not seen as a first-class feature in the others from the evidence gathered (E5 — needs confirmation).
- **Where FireLLM lags:** multi-turn execution (PyRIT, promptfoo have it), breadth of providers, live RAG poisoning, confirmed agent/tool-call observation.
- **Do not over-read counts:** "210+ attacks" (Augustus) / "120+ probes" (garak) / "233 `.fllm`" (FireLLM) are **not** comparable units — templates ≠ distinct techniques. FireLLM's 233 collapse to ~a few dozen distinct techniques (DAN-family, cipher converters, crescendo variants, garak app-sec seeds).
