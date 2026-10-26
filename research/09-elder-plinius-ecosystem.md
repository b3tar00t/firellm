# 09 — Elder-Plinius Ecosystem

Owner: GitHub `elder-plinius` (Pliny the Prompter), https://github.com/elder-plinius. Star counts/dates from third-party aggregators (star-history, githublb, SourcePulse), approximate, access 2026-10-26. **READMEs for the last four were not read in full this pass** — descriptions are from listings/aggregators and marked low-confidence.

## Relationship map

| Repo | Purpose | Core methods | Inputs/outputs | Artifacts | License | FireLLM relevance |
|---|---|---|---|---|---|---|
| **L1B3RT4S** | Jailbreak prompt collection | Role-play, creative phrasing, formatting bypass scaffolds | In: none; Out: prompt templates | Payload corpus | (repo) | Payload source (dual-use). Overlaps PyRIT jailbreak set already imported |
| **CL4R1T4S** | Leaked system prompts (ChatGPT/Claude/Gemini/Grok/Perplexity/Cursor/Lovable/Replit/…) | Collection of verbatim leaked prompts | Out: prompt text | Prompt/dataset | (repo) | **Already imported** as 74 `ground_truth` `.fllm`. Fingerprint/confirmation ground truth |
| **OBLITERATUS** | "Obliterate the chains" (listing tagline) | Unknown (Python) | Unknown | Unknown | AGPL-3.0 | **Low confidence.** Possibly abliteration / refusal-removal (weight-space) — NOT verified. **AGPL-3.0 is a licensing concern for reuse** |
| **T3MP3ST** | "Autonomous red-teaming platform; multi-agent offensive-security meta-harness" (listing) | Multi-agent orchestration (TypeScript) | Unknown | Framework | AGPL-3.0 | Conceptually overlaps the multi-turn/agent engine FireLLM lacks; **AGPL-3.0 restricts reuse**; contents unverified |
| **ST3GG** | "Steganography suite" (listing) | Encoding/representation hiding | Unknown | Tool | Unknown | Possible encoding/stealth transforms (converter-adjacent); unverified |
| **G0DM0D3** | "LIBERATED AI CHAT" (listing) | Unknown | Unknown | App/prompt | Unknown | Likely end-user jailbreak chat, **not** a testing framework; low FireLLM relevance |

## Categorization (per §5.2)
- **Payload/prompt collections:** L1B3RT4S (jailbreak prompts), CL4R1T4S (leaked system prompts).
- **Attack generation / harness:** T3MP3ST (multi-agent red-team harness — unverified).
- **Model modification / weight-space:** OBLITERATUS (possible abliteration — unverified).
- **Stealth/encoding:** ST3GG (steganography — unverified).
- **End-user jailbreak app:** G0DM0D3 (not a security-testing tool — unverified).

Do **not** assume these are designed to be combined into one framework; the evidence shows a loosely related personal-research constellation, not an integrated suite.

## FireLLM overlap assessment
- **Already have:** CL4R1T4S content (imported). L1B3RT4S overlaps the PyRIT jailbreak scaffolds already present — marginal addition, same `goal:injection` single-shot bucket, diminishing returns under the ≤10/goal budget (see earlier Option-A analysis). Same scaffold-vs-filled-answer triage required.
- **Potentially useful but gated:** T3MP3ST (multi-agent harness) and ST3GG (encoding) are conceptually adjacent to FireLLM's multi-turn gap and converter library — **but AGPL-3.0 (where it applies) is incompatible with FireLLM's MIT license for code reuse**; treat as reference only, not code import.
- **Irrelevant/out-of-scope:** OBLITERATUS (weight-space refusal removal) and G0DM0D3 (jailbreak chat) are model-modification / end-user artifacts, not application-security testing capabilities.

## What the ecosystem adds vs duplicates
- **Adds:** nothing FireLLM lacks that is both (a) in-scope for application security and (b) license-clean for reuse, based on verified evidence. CL4R1T4S value is already captured.
- **Duplicative:** L1B3RT4S vs the imported PyRIT jailbreak corpus.
- **Needs verification before any use:** OBLITERATUS, T3MP3ST, ST3GG, G0DM0D3 — read READMEs/licenses in a continuation pass; several are AGPL and/or model-modification, which likely rules them out regardless.
