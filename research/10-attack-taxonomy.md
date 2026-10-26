# 10 — Attack Taxonomy & Coverage Matrices

Taxonomy derived from the research, anchored loosely to OWASP LLM Top 10 2025. Two matrices kept distinct per §6.

## Matrix A — Research→Tool coverage
Which techniques in the literature are exposed as reusable tests, and by which tools. (N=native, P=partial, R=research-only, —=none; FireLLM column = current state.)

| Technique | Key paper | PyRIT | garak | promptfoo | FireLLM |
|---|---|---|---|---|---|
| Direct prompt injection | — | N | N | N | **N** |
| Indirect prompt injection | Greshake 2302.12173 | N | N (latentinjection) | N | **P** (indirect/RAG module) |
| RAG corpus poisoning | PoisonedRAG 2402.07867 | P | P | P | **P (simulated only)** |
| Jailbreak / policy bypass | (DAN etc.) | N | N (dan) | N | **N** (167 scaffolds) |
| Crescendo (multi-turn) | 2404.01833 | N | P | P | **R→stored, not executed** |
| PAIR | 2310.08419 | N | — | P | **stored (strategy)** |
| TAP | 2312.02119 | N | N (tap) | P | **stored (strategy)** |
| Skeleton Key | MS blog 2024 | N (dataset) | — | P | **stored (strategy)** |
| Many-shot | Anil 2024 | N | P | P | **technique known; corpus quarantined** |
| System-prompt extraction | — | N | N | N | **N + model-specific confirm (new)** |
| Tool/agent misuse | — | P | P | N | **P (informational, unconfirmed)** |
| Memory/persistence poisoning | Rehberger PoCs | P | — | P | **—** |
| Multimodal injection | (various) | N | P | P | **—** |
| Encoding/cipher bypass | CipherChat etc. | N (converters) | N | P | **N (18 converters stored; not all wired)** |

## Matrix B — Security-evidence coverage
Which techniques have research (E3), independent reproduction (E2), and real-world/production evidence (E1).

| Technique | Research (E3) | Indep. repro (E2) | Real-world (E1/PoC) |
|---|---|---|---|
| Indirect prompt injection | ✅ | ✅ | ✅ (Bing, memory, email agents) |
| Direct injection / jailbreak | ✅ | ✅ | ✅ (widespread) |
| RAG poisoning | ✅ (PoisonedRAG) | partial | weak (mostly lab/benchmark) |
| Crescendo | ✅ | ✅ (USENIX) | partial |
| TAP / PAIR | ✅ | ✅ | lab-level (model, not app) |
| Skeleton Key | ✅ (vendor) | partial | vendor-reported multi-model |
| Many-shot | ✅ | ✅ | lab-level |
| System-prompt leakage | partial | ✅ | ✅ (many real leaks → CL4R1T4S) |
| Tool/agent misuse (excessive agency) | ✅ | ✅ | ✅ (Rehberger, ZombieAgent) |
| Memory/persistence poisoning | partial | ✅ | ✅ (SpAIware) |
| Multimodal injection | ✅ | partial | partial |

**Do not conflate the matrices:** a technique can be well-tooled (A) yet thin on production evidence (B) — e.g. TAP/PAIR (strong tooling, lab-only impact) — or strong in B but weakly tooled as *application* tests (A) — e.g. memory-persistence poisoning.

## Per-class confidence
- High: direct/indirect PI, jailbreak, system-prompt leakage, excessive agency (strong on both axes).
- Medium: RAG poisoning (research-strong, production-thin), Crescendo/Skeleton Key.
- Lower / under-examined this pass: multimodal, supply-chain/fine-tuning, cross-user/session isolation.
