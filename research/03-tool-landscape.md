# 03 — Tool Landscape Profiles

Profiles for the significant tools investigated. Counts/dates are labelled by source type; many are maintainer- or aggregator-reported and not read from the primary GitHub release page this pass.

## garak (NVIDIA)
- **Repo:** https://github.com/NVIDIA/garak · docs https://docs.garak.ai · **License:** Apache-2.0 (per docs).
- **Status:** Active. Release **conflict**: one source `v0.17.0` (2026-09-09), another `v0.14.0` (Feb 2026) — **unverified**.
- **Scope / threat model:** LLM vulnerability scanner — sends many adversarial "probes" at a model, runs "detectors" over responses. Plugin architecture: probes / detectors / generators / evaluators.
- **Attack classes (native):** prompt injection (`promptinject`, `latentinjection`), jailbreaks (`dan`), training-data & system-prompt leakage, malware/XSS generation, encoding bypasses, toxicity; TAP probe wraps Robust Intelligence's implementation.
- **Model support:** any model reachable via API/generator plugin; local models supported.
- **Adaptive/multi-turn/multimodal:** "static, dynamic, and adaptive" probes (E4). ~120+ probe modules (secondary). Primarily **single-turn model-level** testing.
- **Evaluation:** automated detectors (string/classifier). **Model-level, not application-level.**
- **Relevance:** Overlaps FireLLM's injection/jailbreak probing and fingerprinting. Differs: FireLLM targets the *application* (HTTP endpoint, RAG, defense fingerprint) rather than a raw model generator. **Evidence: E4** (maintainer/docs).

## PyRIT (Microsoft)
- **Repo:** github.com/microsoft/PyRIT · **License:** MIT (Python 3.10–3.13).
- **Status:** Active; AppSecSanta snapshot (2026-02-07) reports `v0.11.0` (Feb 2026), ~3.4k stars / 661 forks / 117 contributors (**secondary, unverified**).
- **Scope:** Red-teaming *framework/library* (not a one-shot scanner). Orchestrators (multi-turn), converters (prompt transforms), scorers, memory.
- **Attack classes:** multi-turn orchestration (Crescendo, TAP, PAIR, skeleton key present as datasets/executors), converters (base64, ciphers, codechameleon…), many-shot, jailbreak templates.
- **Adaptive/multi-turn:** **Yes** — core strength. Multimodal supported.
- **Evaluation:** scorers (rule + model-judged).
- **Relevance:** FireLLM already **absorbed PyRIT's dataset library** (233 `.fllm`). PyRIT's orchestrators are exactly the multi-turn engine FireLLM lacks. **Evidence: E4** + dataset directly inspected (E-repo).

## promptfoo
- **Repo/site:** https://promptfoo.dev · red-team docs /red-teaming. 
- **Status:** Active. **Unverified** secondary claim: "acquired by OpenAI March 2026" (single source, no primary) — flag, do not rely.
- **Scope:** Open-source eval + red-team for LLM **applications**; adaptive, generates attacks on-the-fly (not canned lists).
- **Attack classes:** 50+ vulnerability types incl. direct/indirect PI, jailbreaks, PII/data leak, insecure tool use, RAG poisoning; OWASP LLM Top 10 / NIST AI RMF alignment (E4).
- **Interfaces:** HTTP API, browser, direct model; CI/CD; runs locally.
- **Relevance:** Closest philosophical match to FireLLM (application-level, adaptive). promptfoo is broader/more mature on eval+compliance; FireLLM is narrower/offense-focused with defense fingerprinting. **Evidence: E4** (vendor docs).

## Augustus (Praetorian)
- **Repo:** https://github.com/praetorian-inc/augustus · **License:** Apache-2.0 · single Go binary.
- **Status:** Active (2026). Install `go install github.com/praetorian-inc/augustus/cmd/augustus@latest`.
- **Scope:** LLM vulnerability scanner, **210+ adversarial attacks**, **28 providers** (maintainer-reported, E4): prompt injection, jailbreaks, encoding exploits, data extraction. Explicitly "inspired by garak."
- **Relevance:** Direct competitor to garak/FireLLM on injection/jailbreak/extraction. Go binary = easy distribution (FireLLM is a Python lib/CLI). **Evidence: E4.**

## DeepTeam (Confident AI)
- Red-teaming framework for LLMs/LLM systems; open-sourced ~March 2025; CI/CD-oriented; "40+ vulnerability probes" (secondary, E4). Python-first, Promptfoo-like workflow.

## Giskard
- Python-first testing framework, "40+ vulnerability probes" (secondary, E4). Broader ML testing heritage. Primary repo not read this pass.

## LLM Guard
- **Runtime protection** (not offense). MIT, "35 scanners" (secondary). Input/output filtering: harmful language, data leakage, PI/jailbreak detection. **Defensive** — relevant to FireLLM as a *target defense* to fingerprint/evade, not a peer attacker.

## Rebuff
- Prompt-injection **detector** (defensive): heuristic filtering + vector detection + LLM analysis + canary tokens. "Originally Protect AI" (secondary, unverified). Relevant as a defense class FireLLM should be able to fingerprint.

## Unresolved / not-found
- **TriShieldRAG:** single Substack mention ("integrity of retrieved knowledge"); no repo. **Wallbreaker, IPI-Scanner:** no primary source found. Recorded, not described.

See `04-tool-comparison-matrix.md` for the matrix and `09-elder-plinius-ecosystem.md` for L1B3RT4S/CL4R1T4S/etc.
