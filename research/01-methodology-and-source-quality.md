# 01 — Methodology and Source Quality

**Research cutoff date:** 2026-10-26 (date searches were run).
**Mode:** Read-only. No application code, tests, config, or dependencies were modified. No tools were installed or executed. No testing against third-party targets.

## Methods

- Read-only inspection of the FireLLM repository (README, module source, payload library, tests) for the baseline (see `02-firellm-baseline.md`).
- Web search (standard + extended) for tool identity/status, academic papers, real-world disclosures, and the elder-plinius repositories.
- Primary sources preferred (arXiv abstracts, vendor blogs, official GitHub repos, OWASP). Where only secondary/aggregator sources were available, findings are labelled accordingly.

## Search terms (representative, not exhaustive)

`garak LLM vulnerability scanner`, `Microsoft PyRIT release status`, `promptfoo red team`, `elder-plinius L1B3RT4S CL4R1T4S OBLITERATUS T3MP3ST`, `Crescendo multi-turn jailbreak arxiv`, `Tree of Attacks Pruning PAIR arxiv`, `Skeleton Key jailbreak Microsoft`, `many-shot jailbreaking Anthropic`, `Johann Rehberger prompt injection memory exfiltration`, `Greshake indirect prompt injection`, `PoisonedRAG arxiv`, `OWASP Top 10 LLM 2025`, `DeepTeam Giskard LLM Guard Rebuff`, `TriShieldRAG Wallbreaker IPI-Scanner Augustus`.

## Inclusion / exclusion

- **Included:** tools/papers/incidents with at least one locatable primary or strong secondary source.
- **Excluded / unresolved:** names for which no primary source was found are recorded as such rather than described (see below).

## Evidence classification (per the brief)

- **E1** Production evidence — documented impact in a real deployed system.
- **E2** Independent reproduction.
- **E3** Published evaluation (peer-reviewed / preprint / structured benchmark).
- **E4** Maintainer claim (unverified independently).
- **E5** Hypothesis / proposed gap.

## Coverage confidence

- **Tools:** medium-high for garak, PyRIT, promptfoo, Augustus, elder-plinius repos; medium for DeepTeam/Giskard/LLM Guard/Rebuff (secondary sources only); **low / unresolved** for TriShieldRAG, Wallbreaker, IPI-Scanner (see below).
- **Papers:** high for the six named techniques (Crescendo, TAP, PAIR, Skeleton Key, many-shot, indirect PI) + PoisonedRAG; partial for multimodal and supply-chain (not deeply searched this pass).
- **Incidents:** medium — Rehberger line of work well-covered via secondary sources; broader CVE enumeration **not** completed this pass.

## Inaccessible / unverified / unresolved sources

- **garak latest release:** conflicting — one source `v0.17.0` (dated 2026-09-09), another `v0.14.0` (Feb 2026). GitHub releases page not directly read. Treat as unverified.
- **promptfoo "acquired by OpenAI March 2026":** single secondary source (AppSecSanta), **no primary corroboration**. Labelled unverified.
- **PyRIT release (`v0.11.0`, Feb 2026), stars/forks/contributors:** AppSecSanta snapshot, not read from GitHub directly.
- **elder-plinius star counts / last-updated dates:** third-party aggregators (star-history, githublb); approximate.
- **Repo contents for OBLITERATUS / T3MP3ST / ST3GG / G0DM0D3:** READMEs **not read in full** this pass — only listing/aggregator descriptions. Marked low-confidence; continuation required.
- **TriShieldRAG:** one mention (a Substack roundup), no repo link. **Wallbreaker, IPI-Scanner:** no primary source found. Recorded as unresolved, not described.
- **Citation counts:** not collected (would need Scholar/Semantic Scholar access); omitted rather than fabricated.

## Conflicts and resolution

- garak version conflict → reported both, flagged unverified.
- promptfoo acquisition → reported as single-source/unverified.
- Rehberger OpenAI response framing ("dismissed as non-security" vs "responded swiftly") → reported the disagreement rather than picking one.

## Explicit non-exhaustive areas

Multimodal injection tooling, model supply-chain/fine-tuning attacks, the full CVE/advisory index (§4.3, §08), benchmarking landscape (§13) depth, and exhaustive tool discovery beyond the named set were **not** completed. See `00-executive-summary.md` continuation plan.
