# FireLLM — Next Session Plan

Derived from the `research/` dossier (baseline, gap analysis, tool landscape, elder-plinius) and the strategic Q&A. Horizon: ~4–6 weeks toward production-grade, community-ready offensive capability. No work has started on any item below.

## Guiding decision
Ambition: **the go-to tool for LLM security testing** — what sqlmap is to SQLi and Burp is to web app pentesting. The target user reaches for FireLLM first, over garak / promptfoo / PyRIT.

The build order is unchanged by that ambition — it is what any go-to tool needs regardless — but "go-to" *raises* the stakes on two things rather than lowering them:
1. **Trust is the moat.** sqlmap and Burp are trusted because they are *right*. A bigger audience means one viral "confirmed a vuln that wasn't real" thread does more damage, so the measured precision/recall release gate (Phase 4) is more non-negotiable, not less.
2. **Wedge before breadth.** Win the differentiated core first (confirmed agent/tool-call abuse), then widen to full coverage (single-turn, multi-turn, agent, RAG, every provider). Breadth without the confirmed-findings core is just "a worse promptfoo."

Build order: a differentiated wedge (confirmed agent/tool-call abuse), earned trust (measured precision/recall), then breadth + a frictionless contribution pipeline.

---

## Phase 0 — Fix first (credibility, ~1 day, before any feature)

These are public-release blockers a reviewer catches immediately.

- [ ] **Scrub "PyRIT archived" claim.** Research shows active releases into 2026. Remove from any doc/comment. (~15 min)
- [ ] **OWASP tag precision.** Imported `.fllm` mis-tag objectives. Fix loader objective→OWASP map and re-emit:
  - `dump_credentials` → **LLM02** (Sensitive Information Disclosure), not LLM06.
  - `extract_system_prompt` → **LLM07** (System Prompt Leakage), not LLM01.
  - Keep `achieve_tool_misuse`/`escalate_privileges` → LLM06 (Excessive Agency).
  - Scripted re-emit across `payloads/`. (~2 hr)
- [ ] **README multi-turn overclaim.** Downgrade "multi-turn attack chains" from shipped to roadmap until Phase 2 lands. Mark converter `.fllm` as stored-not-wired. (~30 min)
- [ ] Re-run suite; confirm still green after tag re-emit.

---

## Phase 1 — G2: Response-confirmed agent tool-call observation (weeks 1–2, ~8–10 days)

**Top priority — the differentiating wedge.**

- **What:** Instrument a target harness (tool-proxy / MCP shim) that logs actual tool invocations. `scan_runner` compares the dispatched attack instruction against the observed tool-call log → agent findings become **response-confirmed**, not informational.
- **Why first:** highest real-world evidence (indirect-PI → tool/agent abuse: Rehberger, ZombieAgent); clear ecosystem deficit; validatable (tool log = ground truth → low FP); matches FireLLM's own roadmap note.
- **Depends on:** new instrumented agent target under `test-targets/`. No blocker.
- **Unlocks:** the one thing the README admits it can't do — confirmed OWASP LLM06 Excessive Agency / tool-misuse findings.
- **Done when:** an instrumented local agent target logs tool calls; FireLLM's verdict matches the log; agent findings reported as confirmed with evidence.

**Status (done this session):** `test-targets/vulnagent` instrumented target built — deterministic rule-based agent (the tool-call log is the ground-truth oracle), planted weaknesses A1–A4, inline `tool_calls` + out-of-band `GET /_toollog`. FireLLM side: `AgentObserver` (dispatch under a session id, read the log) and `AgentTester.confirm()` (upgrades a string hypothesis to response-confirmed only when the attack drove the expected tool(s); chain rules need all tools; IDOR needs an out-of-scope id). `scan_runner.run_live_scan` takes an `agent_observer`; the agent branch confirms against the log, and the legacy no-observer path is now `confirmed=False` (informational), closing the old overclaim. 165 tests pass; oracle + confirmation + wiring covered.

**Full G2 sign-off: DONE.** Live end-to-end proven over real loopback TCP sockets (not just in-process). The target's pure logic was extracted into `agent_core.py`, served two ways: `app.py` (FastAPI, for Docker, port 8003 in `test-targets/docker-compose.yml`) and `serve.py` (stdlib `http.server`, zero third-party deps — runs anywhere). Two always-on suite tests bring up `serve.py` on an ephemeral port and drive the real path: `test_observer_confirms_over_real_socket` (`AgentObserver` → `/chat` + `/_toollog` → `confirm()` confirmed, incl. IDOR out-of-scope) and `test_scan_runner_e2e_over_real_socket` (full `run_live_scan --modules agent` yields confirmed LLM06 findings). Dev env note: FastAPI could not be used locally — the `.venv` lives on OneDrive and pip-installed files became unreadable cloud placeholders (`OSError: [Errno 22]`); the stdlib server sidesteps that and is the better dependency-free default.

---

## Phase 2 — G1: Multi-turn execution engine (weeks 2–4, ~10–12 days)

**Biggest build. Closes the README overclaim honestly.**

- **What:** `ConversationManager` + stateful delivery (refactor `PromptDeliveryAdapter.send` to accept message history; `HTTPAdapter` multi-message body). Wire the 18 `strategy` `.fllm` (crescendo, skeleton_key, tree_of_attacks, pair, flip_attack) into a per-turn loop that uses **SuccessEvaluator** for the escalate/stop verdict.
- **Why second:** real technique (Crescendo/TAP/Skeleton Key, E3); corpus already imported; depends on SuccessEvaluator (done) and reuses the G2 harness.
- **Depends on:** SuccessEvaluator (✅ done), delivery refactor (single-shot → history), G2 harness.
- **Unlocks:** Crescendo/Skeleton Key actually run (currently stored-not-executed).
- **Done when:** a known multi-turn-susceptible local target is driven turn-by-turn; stops on first confirmed objective; regression test added.

---

## Phase 3 — G3: Live RAG corpus poisoning (weeks 4–5, ~6–8 days)

- **What:** controllable local vector store in the harness; inject N malicious docs (PoisonedRAG method, arXiv:2402.07867); confirm attacker-chosen answer surfaces. Replaces today's heuristic simulation with execution.
- **Why third:** most objectively validatable gap (attacker answer = unambiguous ground truth); reuses VulnRAG targets.
- **Depends on:** local vector store in `test-targets/`.
- **Unlocks:** real OWASP LLM04/LLM08 testing vs current simulation.

---

## Phase 4 — G5 + contribution pipeline + eval set (weeks 5–6)

Cheap, high-leverage, release-enabling. Can partly overlap earlier phases.

- [ ] **G5 — Provider fingerprint breadth (~2–3 days).** Wire CL4R1T4S self-ID strings into `response_analyzer` so it fingerprints **xai / meta / mistral / perplexity** (currently only openai/anthropic/gemini/ollama). Compounds G1–G3 (right provider → right ground-truth markers).
- [ ] **Payload contribution pipeline (~3–4 days) — the real "plugin" surface for a payload-driven tool.**
  - `CONTRIBUTING-payloads.md`: how to author a `.fllm`, required fields, scaffold-vs-filled-answer rule (no uplift content; see `many_shot` quarantine precedent).
  - `fllm-lint` / `firellm validate` CLI command that validates a `.fllm` via PayloadLoader.
  - CI check that runs the validator on PRs.
  - **`confirmed_finding` promotion path:** unconfirmed → confirmed once a reproduction is attached. Payload-library strategy shifts from "import more corpora" to "curate + provenance + confirmed-finding."
- [ ] **Minimal labeled eval set (~1 week, release gate — see caveat).** Extend `test-targets/` to ~5–10 local targets (vulnerable + hardened variants) with known answer keys. Publish measured **precision/recall**. Convert the n=1 blind test into a defensible baseline. Ship with "validated on N local targets: P precision / R recall; community results welcome."
- [ ] Harden, docs, repeatable VulnRAG-based eval run.

---

## Skip (not worth building yet)

- **L1B3RT4S bulk import** — duplicates imported PyRIT scaffolds; diminishing returns under the ≤10/goal budget; same quarantine liability. Community value is *novel confirmed findings with provenance*, not re-importing a public scrape.
- **Dynamic code-plugin runtime** (load arbitrary Python attack modules) — security/maintenance liability on an offensive tool; premature. (The `.fllm` contribution path above is the plugin surface that matters now.)
- **G4 — custom-prompt leak confirmation** — real need, but no reliable validation oracle (high FP) without planted canaries. Defer.
- **G6 — authoritative app-level benchmark** — keep VulnRAG as internal regression; don't over-invest in "the" standard.
- **Multi-target orchestration, distributed scanning, PyPI release** — premature until G1/G2 land; they scale a tool that isn't yet confirming its core findings.
- **elder-plinius OBLITERATUS / T3MP3ST / ST3GG / G0DM0D3** — AGPL and/or model-modification; out of scope and license-incompatible with MIT. Reference only, no code reuse.

---

## Biggest unaddressed risk (carry into every phase)

**FireLLM has no measured false-positive / false-negative rate on diverse targets, and community usage will NOT supply it** — FPs get silently distrusted (lost user, no data), the wild has no ground truth, and one public "confirmed a vuln that wasn't real" thread outweighs 100 quiet wins. Releasing on the n=1 blind test alone risks an unrecoverable credibility hit in someone's engagement. Mitigation is the Phase-4 labeled eval set: **do not public-release without published precision/recall on local ground-truth targets.** This is the least glamorous item and the one most likely to be skipped — treat it as a hard release gate.

### Secondary risks
- **Being a worse PyRIT/promptfoo** (they have Microsoft/OpenAI backing, multi-turn, mindshare). Mitigation: hold the G2 wedge — confirmed agent/tool-misuse, app-level — don't compete on single-turn breadth.
- **Solo-maintainer bus factor / contribution flywheel stalling.** Mitigation: make the contribution pipeline frictionless (Phase 4) before release.
- **Target drift** (LLM defenses change monthly) — fingerprints/payloads rot; budget ongoing upkeep.
- **Dual-use scrutiny** on a public offensive tool with jailbreak corpora — keep the authorized-use framing, provenance, and quarantine discipline explicit.

---

## Start-of-next-session checklist
1. Do Phase 0 (credibility fixes), re-run suite.
2. Design the G2 instrumented agent target before coding scan_runner changes.
3. Keep every phase gated by a regression test and honest README state.
4. Public release only after the Phase-4 eval numbers exist.
