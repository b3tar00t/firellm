# 14 — Gap Analysis

A gap counts only where existing capability is inadequate for a real security-testing need (per §7). Each candidate is tested against: already implemented elsewhere? available via integration? research vs engineering vs documentation problem? dataset already solves it? what blocks existing tools? would it improve detection/coverage/reproducibility? how to validate? FP risk?

## Candidate gaps

### G1 — Application-level multi-turn execution with per-turn confirmation
- **Need:** Crescendo/Skeleton Key/TAP are real (E3) and FireLLM has the strategy corpus, but delivery is single-shot; strategies are stored, never executed.
- **Elsewhere?** PyRIT and promptfoo have multi-turn orchestration. So the *technique* is not novel.
- **Problem type:** **engineering**, not research (needs stateful delivery + ConversationManager + per-turn SuccessEvaluator verdict).
- **Differentiation:** doing it at the *application HTTP layer with defense-aware variant selection and objective-specific per-turn confirmation* is less common than model-level multi-turn. Plausible but not proven differentiation.
- **Validation:** replay against VulnRAG targets + a known multi-turn-susceptible local target; measure turns-to-confirm.
- **FP risk:** medium (escalation can "confirm" on partial compliance) — mitigated by canary-based success_criteria.
- **Class: Partially-addressed need** (addressed in peer tools; unmet *in FireLLM*; engineering not research).

### G2 — Response-confirmed agent/tool-call observation
- **Need:** the dominant real-world impact class (excessive agency + output handling, Rehberger/ZombieAgent, E1/PoC) requires observing whether a tool was actually invoked. FireLLM's agent findings are **informational only**.
- **Elsewhere?** Partial in promptfoo (tool-use tests); generally weak across tools for true tool-call observation at the app boundary.
- **Problem type:** **engineering + harness design** (need a target harness that exposes tool-call traces, or MCP/tool-proxy instrumentation).
- **Differentiation:** **Strong candidate.** Turning agent findings from informational → response-confirmed via a tool-call-observing harness addresses a high-evidence class few tools do rigorously at app level.
- **Validation:** instrumented local agent target that logs tool invocations; compare FireLLM verdict vs ground-truth tool log.
- **FP risk:** low once tool calls are observed (ground truth available).
- **Class: Verified unmet need** (for FireLLM and largely the ecosystem).

### G3 — Live RAG corpus poisoning (not simulation)
- **Need:** PoisonedRAG (E3, 97% ASR lab) is the canonical injection; FireLLM only *detects/simulates*.
- **Elsewhere?** Research code exists (PoisonedRAG); garak/promptfoo have partial RAG tests.
- **Problem type:** engineering + needs a controllable vector store in the test harness.
- **Validation:** inject N docs into a local store, measure attacker-answer success — directly reproducible against VulnRAG.
- **FP risk:** low (attacker-chosen answer is unambiguous ground truth).
- **Class: Partially-addressed need.**

### G4 — Confirmation on custom-prompt targets (beyond retained boilerplate)
- **Need:** CL4R1T4S markers only confirm system-prompt leaks when vendor boilerplate survives; real deployments use custom prompts. Confirming extraction of a *custom* prompt needs planted canaries or behavioral/instruction-echo evidence.
- **Elsewhere?** Not well solved anywhere; genuinely hard.
- **Problem type:** **research + methodology** (how to prove "this is the target's real system prompt" without knowing it a priori).
- **Validation:** hard — this is the crux; canary-injection in authorized engagements is the only clean oracle.
- **FP risk:** **high** (false "leak" claims). 
- **Class: Plausible but unverified opportunity** — valuable, hard to validate reliably.

### G5 — Provider fingerprint breadth + self-ID ground truth
- **Need:** analyzer covers only 4 vendors; CL4R1T4S has exact self-ID strings for xai/meta/mistral/perplexity.
- **Problem type:** **documentation/engineering** (wire known identity strings into the analyzer). Low novelty, low risk, quick win.
- **Class: Partially-addressed need (cheap).**

### G6 — Reproducible application-level benchmark + regression
- **Need:** most benchmarks are model-level; few capture application trust-boundary impact with regression testing. FireLLM has VulnRAG targets + ground-truth rubrics — a seed for this.
- **Elsewhere?** promptfoo/CI exist but app-architecture realism is thin (industry-wide gap).
- **Problem type:** engineering + methodology.
- **Class: Verified unmet need (ecosystem-wide)**, but hard to validate as "the" benchmark.

### Already-addressed / de-prioritize
- More jailbreak payloads (L1B3RT4S bulk import): **already addressed** by imported PyRIT corpus; diminishing returns under ≤10/goal budget.
- Generic single-turn injection/jailbreak: mature across garak/PyRIT/promptfoo/Augustus — not white space.

## Prioritization (1–5; higher = stronger. Subjective, documented criteria, not objective truth)

Criteria: **Impact** (security value), **Relevance** (real-world evidence), **Deficit** (ecosystem coverage gap), **Feasible** (engineering tractability), **Validatable** (can we prove it works objectively), **Differentiation**.

| Gap | Impact | Relevance | Deficit | Feasible | Validatable | Diff. | Note |
|---|---|---|---|---|---|---|---|
| G2 agent tool-call confirmation | 5 | 5 | 4 | 3 | 4 | 4 | Strongest evidence-backed; builds on FireLLM's stated roadmap |
| G1 multi-turn execution | 4 | 4 | 3 | 3 | 4 | 3 | Engineering; peers have it; validatable on VulnRAG |
| G3 live RAG poisoning | 4 | 3 | 3 | 3 | 5 | 3 | Highly validatable; research-strong/production-thin |
| G6 app-level benchmark | 4 | 4 | 4 | 2 | 2 | 4 | Valuable, hard to validate as authoritative |
| G5 fingerprint breadth | 2 | 3 | 3 | 5 | 4 | 2 | Cheap quick win |
| G4 custom-prompt leak confirmation | 4 | 4 | 4 | 2 | 1 | 3 | High FP risk; validation is the blocker |

## Summary
- **Strongest evidence-backed:** G2 (response-confirmed agent/tool-call observation) — high real-world evidence, clear deficit, validatable with an instrumented harness, aligns with FireLLM's own roadmap note.
- **Attractive but already addressed:** bulk jailbreak expansion; generic single-turn testing.
- **Too speculative / hard to validate now:** G4 (custom-prompt leak confirmation) — real need, but no reliable oracle without planted canaries.
- **Valuable-but-hard-to-evaluate:** G6 (application-level benchmark).
- **Cheap quick win:** G5 (provider fingerprint breadth from CL4R1T4S self-ID strings).

No architecture chosen; no implementation. Decision deferred to review per the brief.
