# 00 — Executive Summary

**Research cutoff:** 2026-10-26. **Mode:** read-only; no code/config/dependency changes, no tool installs, no third-party testing. Evidence tiers E1–E5 per `01`. This dossier is deliberately **not** exhaustive; see "Unfinished work" below.

## Directory note
The brief's 16-file structure was consolidated to avoid empty stubs. Delivered: `01` methodology+sources, `02` FireLLM baseline, `03` tool profiles, `04` tool matrix, `05` literature+lineage, `07` real-world incidents, `09` elder-plinius, `10` taxonomy + both coverage matrices, `14` gap analysis, `15` bibliography. Folded/not produced: `06` paper-index (into `05`/`15`), `08` CVE index (partial, in `07`), `11`/`12` (into `10`), `13` benchmarking (partial, below).

## What the ecosystem already does well
- **Single-turn prompt injection and jailbreak testing** is mature and commoditized: garak (NVIDIA, model-level probes), PyRIT (Microsoft, red-team framework), promptfoo (application-level, adaptive), Augustus (Praetorian, Go scanner). (E4, vendor/docs.)
- **Multi-turn orchestration** (Crescendo, TAP, PAIR, Skeleton Key) exists as reusable tooling in **PyRIT** and partially promptfoo. (E3 papers + E4 tooling.)
- **Defensive runtime filtering** is covered by LLM Guard and Rebuff.

## Tools most relevant to FireLLM
- **PyRIT** — FireLLM already absorbed its dataset library; its orchestrators are the model for the multi-turn engine FireLLM lacks.
- **promptfoo** — closest philosophical peer (application-level, adaptive, OWASP-aligned); the bar for breadth/compliance.
- **garak / Augustus** — the single-turn scanner baseline FireLLM should not merely re-create.

## Attack classes by testing maturity
- **Mature:** direct/indirect prompt injection, jailbreak/policy bypass, system-prompt leakage.
- **Partial / experimental:** RAG poisoning (strong research, mostly simulated in tools), multi-turn execution (tooled in PyRIT, **stored-not-executed in FireLLM**), tool/agent misuse (mostly *informational*, rarely tool-call-confirmed).
- **Weak / under-served:** response-confirmed agent tool-call observation at the app boundary; memory/persistence poisoning as a repeatable app test; application-level benchmarks with regression; confirmation of leaks on **custom** (non-boilerplate) system prompts.

## What the real-world evidence shows
- The durable, cross-product class is **indirect prompt injection via untrusted retrieved/third-party content**, escalated through **connected capabilities** (memory, email, browsing) into **persistence and data exfiltration** — Greshake et al. (E2/E3) and the Rehberger line (SpAIware, Gemini memory, ZombieAgent; PoC/E1-adjacent). Impact is usually an **application/architecture** failure (excessive agency + insecure output handling), not raw model misbehavior. Lab jailbreak success (TAP/PAIR/many-shot) does **not** equal production impact.

## What the elder-plinius ecosystem contributes
- **CL4R1T4S** (leaked system prompts) — already imported as 74 `ground_truth` markers; useful only where vendor boilerplate survives in the target.
- **L1B3RT4S** (jailbreak prompts) — duplicates the imported PyRIT scaffolds; low marginal value.
- **OBLITERATUS / T3MP3ST / ST3GG / G0DM0D3** — unverified this pass; appear to be weight-space (abliteration), multi-agent harness, steganography, and an end-user jailbreak chat. Several are **AGPL-3.0** and/or model-modification — likely out of scope and license-incompatible with FireLLM's MIT. **Verify before any use.**

## Strongest evidence-backed gaps (detail in `14`)
1. **G2 — Response-confirmed agent/tool-call observation.** Highest real-world evidence, clear ecosystem deficit, validatable with an instrumented harness, matches FireLLM's own roadmap. **Top candidate.**
2. **G1 — Application-level multi-turn execution** with per-turn objective confirmation (engineering, not research; peers have it; validatable on VulnRAG).
3. **G3 — Live RAG corpus poisoning** (most objectively validatable; PoisonedRAG method).
4. **G5 — Provider-fingerprint breadth** from CL4R1T4S self-ID strings (cheap quick win).

## What remains uncertain
- Whether FireLLM's **defense-fingerprint → defense-aware variant selection** is genuinely differentiated vs peers (E5 — not disproven, not confirmed).
- G4 (confirming **custom** system-prompt leaks) is a real need with **no reliable validation oracle** short of planted canaries — high false-positive risk.
- G6 (an authoritative application-level benchmark) is valuable but hard to validate as "the" standard.

## Baseline corrections surfaced
- Prior in-session claim "PyRIT archived March 2026" is **false** (active releases into 2026).
- FireLLM's imported `.fllm` **OWASP tags are imprecise** (e.g. credential dump → LLM06 instead of LLM02/LLM07); worth a cleanup.
- README lists "multi-turn attack chains" as a capability, but delivery is **single-shot** and strategies are **stored, not executed**.

## What to investigate before any architectural decision
- Read the four unverified elder-plinius READMEs + licenses.
- Build the CVE/verified-disclosure index (`08`) and the benchmarking survey (`13`) properly.
- Confirm garak's real latest release and the promptfoo/OpenAI claim from primary sources.
- Prototype-free validation design for G2 (instrumented tool-call target) and G3 (controllable local vector store) before committing.

## Unfinished work (prioritized continuation)
1. Elder-plinius deep read (OBLITERATUS/T3MP3ST/ST3GG/G0DM0D3) — licenses + contents.
2. CVE/advisory index + broader incident enumeration.
3. Benchmarking & evaluation survey (§8/§13): ASR definitions, judge-model bias, query-budget, app-impact metrics.
4. Multimodal, supply-chain/fine-tuning literature.
5. Primary-source verification of flagged unverified items (`01`).

**Stop. No implementation. Awaiting review.**
