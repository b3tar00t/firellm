# 07 — Real-World Exploitation Evidence

Scope note: this pass concentrated on the Johann Rehberger line of work (the most-documented application-level prompt-injection research) plus the foundational indirect-PI demonstrations. A full CVE/advisory enumeration (§4.3) was **not** completed — continuation item. All items below are **proof-of-concept / researcher demonstrations**; no source confirmed in-the-wild criminal exploitation.

## Distinguishing labels used
- **PoC** = researcher demonstration against a real product (not a lab-only model).
- **Vuln report** = reported weakness, impact not fully demonstrated.
- **Lab** = model-level demonstration only.

## Incidents

### ChatGPT memory — false-memory injection (Rehberger, 2024) — PoC, E1-adjacent
- **Component:** ChatGPT "Memory" feature. **Researcher:** Johann Rehberger.
- **Chain:** untrusted content (document/image/web page) → invokes the memory tool → writes persistent false memories (e.g. user "102 years old", "Earth is flat").
- **Trust boundary:** untrusted content → long-term user state.
- **Vendor response:** disputed framing across sources ("initially dismissed as non-security" vs "responded swiftly"); OpenAI mitigated the **exfiltration** path but (per Rehberger via Futurism) **not** the ability of untrusted content to write memories.
- **Sources:** Futurism, LearnPrompting, Anvilogic, SecureTalk interview.

### SpAIware — persistent memory → data exfiltration (Rehberger, Sept 2024) — PoC
- **Component:** ChatGPT macOS app. **Chain:** injected memory carries a standing instruction → leaks subsequent conversation content across new sessions.
- **Impact:** persistent cross-session data exfiltration until the memory is removed.
- **Significance:** demonstrates memory poisoning as a *persistence* mechanism, not a one-shot.

### Gemini delayed-tool-invocation memory poisoning (2025) — PoC
- Planted false long-term memories via delayed tool invocation (secondary summary). Shows the technique generalizes beyond ChatGPT.

### "ZombieAgent" / email-connected agent (Radware, disclosed late-2025, pub Jan 2026) — PoC
- Extended memory/exfiltration approach to an email-connected ChatGPT agent (secondary). Part of the broader "Promptware" framing (CSA research note; arXiv:2601.09625 "Promptware Kill Chain").

### Indirect PI in real apps — Greshake et al. (2023) — PoC, E2
- Bing Chat (GPT-4), GPT-4 code completion, synthetic agents (see `05`). First broad demonstration that retrieved/third-party content controls LLM-integrated apps. Independently echoed by many later disclosures.

## 4.2 — What actually worked (synthesis)
- **Repeatedly across products:** indirect prompt injection via untrusted retrieved/third-party content (email, documents, web pages, tool outputs). This is the single most durable, cross-product class.
- **Persistence:** memory/state poisoning converts a one-shot injection into a durable compromise (SpAIware, Gemini, ZombieAgent).
- **Config-dependent:** exfiltration channels (image markdown, tool calls, URL fetch) depend on the app's output handling and connected tools — mitigated by **application architecture** (egress controls, output sanitization) more than by prompt wording.
- **Required chaining:** highest-impact results combined injection + a connected capability (memory, email, browsing) — i.e. OWASP LLM06 Excessive Agency + LLM05 Improper Output Handling, not model misbehavior alone.

## 4.3 — CVE / disclosure discipline (partial)
- Much of this class is **not** assigned CVEs because the impact arises from **application design / excessive agency / insecure output handling**, not a model-code defect. Classifications are frequently disputed. A dedicated verified-disclosure index (`08-cve-and-disclosure-index.md`) was **not** produced this pass — flagged incomplete.

## Relevance to FireLLM
- The dominant real-world class (indirect PI → exfiltration/persistence via connected capabilities) is exactly what FireLLM tests **only partially**: it covers indirect/RAG injection and (informational) agent abuse, but **cannot observe tool calls**, **has no multi-turn/persistence execution**, and **cannot model egress/output-handling boundaries** end-to-end. See `14-gap-analysis.md`.
