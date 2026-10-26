# 05 — Academic Literature & Technique Lineage

Citation counts intentionally omitted (no Scholar access this pass) rather than fabricated. Dates/IDs from arXiv/vendor pages, access date 2026-10-26. Evidence class noted.

## Indirect prompt injection — Greshake et al. 2023 (E3)
- **"Not what you've signed up for: Compromising Real-World LLM-Integrated Applications with Indirect Prompt Injection"**, arXiv:2302.12173 (submitted 2023-02-23; AISec '23).
- **Finding:** LLM-integrated apps blur data vs instructions; an adversary plants a payload in content the app later retrieves, and the model follows it. Demos: Bing Chat (GPT-4), GPT-4 code completion, synthetic agents. Effects: remote control at inference, persistent compromise, data theft, inter-document "worming", DoS.
- **Tooling:** foundational threat model behind garak `latentinjection`, promptfoo indirect-PI, and FireLLM's indirect/RAG module. **Reusable tool:** partial (concept widely implemented).

## Crescendo multi-turn jailbreak — Russinovich, Salem, Eldan 2024 (E3)
- **"Great, Now Write an Article About That: The Crescendo Multi-Turn LLM Jailbreak Attack"**, arXiv:2404.01833 (v1 2024-04-02; v3 2025-02-26; USENIX Security '25).
- **Finding:** benign-looking multi-turn escalation that references the model's own prior replies; inputs lack identifiable malicious content, evading input filters. Introduces **Crescendomation** (automated). Tested on ChatGPT, Gemini Pro/Ultra, Llama-2-70b-chat, Anthropic. "29–71% over SOTA" figure is **secondary** (wiki), treat as unverified.
- **Tooling:** implemented in PyRIT executors (`crescendo` — already imported into FireLLM as `strategy` `.fllm`, **not yet executed**).

## PAIR — Chao et al. 2023 (E3)
- **"Jailbreaking Black Box Large Language Models in Twenty Queries"**, arXiv:2310.08419 (from model knowledge; not returned in search — verify).
- **Finding:** attacker LLM iteratively refines a jailbreak prompt against the target in ~20 queries, black-box.
- **Tooling:** PyRIT (`pair`), basis for TAP.

## TAP — Mehrotra et al. 2023 (E3)
- **"Tree of Attacks: Jailbreaking Black-Box LLMs Automatically"**, arXiv:2312.02119 (Google Research/Yale/Robust Intelligence; NeurIPS 2024).
- **Finding:** attacker LLM branches candidate prompts, evaluator LLM prunes weak ones before they hit the target. Reported >80% jailbreak on GPT-4-Turbo/GPT-4o; "~94% GPT-4o, 60% fewer queries than PAIR" is **secondary** (alphaXiv). Branching ↑ success, pruning ↑ query-efficiency.
- **Relation:** PAIR = a single chain of TAP (no branch/prune).
- **Tooling:** PyRIT (TAP attack), garak `tap` probe (wraps Robust Intelligence). Imported into FireLLM as `strategy` `.fllm`, not executed.

## Skeleton Key — Microsoft (Russinovich) 2024 (E2/E4)
- Microsoft Security blog, 2024-06-26, "Mitigating Skeleton Key…". Multi-turn: ask the model to *augment* (add warnings) rather than refuse; once accepted, it complies broadly. Reported effective against Llama3-70b, Gemini Pro, GPT-3.5/GPT-4o, Mistral Large, Claude 3 Opus, Cohere Command R+ (vendor-reported; E4, broad model coverage ⇒ stronger than single-model). In FireLLM as `strategy` `.fllm`, not executed.

## Many-shot jailbreaking — Anil et al. (Anthropic) 2024 (E3)
- Anthropic post 2024-04-02 + NeurIPS 2024 paper. Exploits long context: many fake "compliant" Q&A shots prime the model; effectiveness follows a **power law** up to hundreds of shots. Tested Claude 2.0, GPT-3.5/4, Llama-2-70B, Mistral-7B. Simple mitigations (context cap, fine-tune refuse) insufficient; prompt classification/modification more promising. **Note:** FireLLM **quarantined** PyRIT's `many_shot_examples.json` (filled harmful answers) — the *technique* is in scope, the *filled-answer corpus* was excluded.

## RAG poisoning — Zou et al. 2024, PoisonedRAG (E3)
- arXiv:2402.07867 (Penn State / Illinois Tech). First knowledge-corruption attack on RAG: inject a few malicious texts so the LLM returns an attacker-chosen answer. Reported 97% ASR on NQ with 5 injected texts vs ~2.7M clean. Paraphrasing / perplexity defenses insufficient. Follow-ups: CorruptRAG (arXiv:2504.03957), FilterRAG defense (arXiv:2508.02835).
- **Relevance:** FireLLM's RAG module is detection/simulation; PoisonedRAG is the canonical *injection* method FireLLM does not execute against a live store.

## XPIA (cross-domain/prompt injection automation)
- Referenced in the brief; Microsoft uses "XPIA" (cross-(domain) prompt injection attack) in its red-team tooling/Crescendo lineage. **Not separately verified with a primary paper this pass** — continuation item.

## Standards anchor — OWASP Top 10 for LLM Apps 2025 (E3/authoritative)
- OWASP GenAI Security Project, v2.0 (announced 2024-11-18/19). LLM01 Prompt Injection, LLM02 Sensitive Information Disclosure, LLM03 Supply Chain, LLM04 Data & Model Poisoning, LLM05 Improper Output Handling, LLM06 Excessive Agency, LLM07 System Prompt Leakage, LLM08 Vector & Embedding Weaknesses, LLM09 Misinformation, LLM10 Unbounded Consumption.
- **Baseline fix flagged:** FireLLM's imported `.fllm` OWASP tags don't match this (e.g. credential dump tagged LLM06 vs correct LLM02/LLM07).

## Artifact availability index
- Public code/data: PoisonedRAG, TAP, PAIR, Crescendomation (via PyRIT), many-shot (Anthropic PDF + NeurIPS), indirect-PI (Greshake). Skeleton Key: technique described, mitigations in blog; implementation via PyRIT datasets.
