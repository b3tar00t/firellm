# 15 — Source Bibliography

Access date for all: 2026-10-26. Tiering: **[P]** primary (arXiv/vendor/official repo), **[S]** secondary/aggregator, **[U]** unverified single-source.

## Tools
- [P] garak — https://github.com/NVIDIA/garak · https://docs.garak.ai · Wikipedia https://en.wikipedia.org/wiki/Garak_(software)
- [S] garak release conflict — https://letsdatascience.com/news/nvidia-garak-adds-modular-llm-vulnerability-scanning-2d001928 · https://appsecsanta.com/garak
- [P] PyRIT — https://github.com/microsoft/PyRIT · announcement coverage https://www.securityweek.com/microsoft-releases-red-teaming-tool-for-generative-ai/ · [S] https://appsecsanta.com/pyrit
- [P] promptfoo — https://promptfoo.dev · https://www.promptfoo.dev/red-teaming · https://promptfoo.dev/docs/red-team/quickstart/ · [U] OpenAI-acquisition claim https://appsecsanta.com/promptfoo
- [P] Augustus — https://github.com/praetorian-inc/augustus · https://www.praetorian.com/blog/introducing-augustus-open-source-llm-prompt-injection/ · [S] https://cybersecuritynews.com/augustus-llm-vulnerability-scanner/
- [S] DeepTeam — https://landscape.jimmysong.io/projects/deepteam/ · [S] Giskard/LLM Guard/Rebuff comparisons — https://appsecsanta.com/ai-security-tools/promptfoo-alternatives · https://is4.ai/blog/our-blog-1/rebuff-vs-llm-guard-comparison-2026-389 · [P] LLM Guard coverage https://www.helpnetsecurity.com/?p=276243
- [S] TriShieldRAG (only mention) — https://packtcyberai.substack.com/p/5-hidden-gem-ai-security-tools-on · Wallbreaker / IPI-Scanner: **no source found**.

## Elder-plinius
- [P] profile — https://github.com/elder-plinius · [P] CL4R1T4S — https://github.com/elder-plinius/CL4R1T4S · [P] L1B3RT4S — https://github.com/elder-plinius/L1B3RT4S
- [S] OBLITERATUS/T3MP3ST/G0DM0D3/ST3GG — https://githublb.vercel.app/owner/elder-plinius · https://www.star-history.com/elder-plinius/cl4r1t4s/ · https://www.sourcepulse.org/projects/1828220 (READMEs not read in full — low confidence)

## Papers
- [P] Indirect PI — Greshake et al. arXiv:2302.12173 — https://arxiv.org/abs/2302.12173
- [P] Crescendo — Russinovich/Salem/Eldan arXiv:2404.01833 — https://arxiv.org/abs/2404.01833 · USENIX Security 25 https://www.usenix.org/conference/usenixsecurity25/presentation/russinovich
- [P] PAIR — Chao et al. arXiv:2310.08419 (from model knowledge; not returned in search — verify)
- [P] TAP — Mehrotra et al. arXiv:2312.02119 — https://arxiv.org/abs/2312.02119
- [P] Skeleton Key — Microsoft Security blog 2024-06-26 — https://www.microsoft.com/en-us/security/blog/2024/06/26/mitigating-skeleton-key-a-new-type-of-generative-ai-jailbreak-technique
- [P] Many-shot — Anthropic 2024-04-02 — https://www.anthropic.com/research/many-shot-jailbreaking · PDF https://www-cdn.anthropic.com/af5633c94ed2beb282f6a53c595eb437e8e7b630/Many_Shot_Jailbreaking__2024_04_02_0936.pdf
- [P] PoisonedRAG — Zou et al. arXiv:2402.07867 — https://arxiv.org/abs/2402.07867 · follow-ups arXiv:2504.03957, arXiv:2508.02835
- [P] OWASP Top 10 for LLM Apps 2025 — https://genai.owasp.org/2024/11/17/owasp-reveals-updated-2025-top-10-risks-for-llms-...

## Real-world incidents (secondary-heavy)
- [S] ChatGPT memory flaw — https://www.anvilogic.com/threat-reports/chatgpt-memory-manipulation-flaw · https://learnprompting.org/blog/prompt-injection-hacking-chatgpt-memories · https://futurism.com/the-byte/insert-false-memory-chatgpt
- [S] Rehberger interview — https://www.strikegraph.com/secure-talk-podcast/hijacking-ai-memoryinside-johann-rehbergers-chatpgpt-security-breakthrough
- [S/P] Promptware — CSA note https://labs.cloudsecurityalliance.org/wp-content/uploads/2026/04/CSA_research_note_promptware_c2_agent_exploitation_20260406-csa-styled.pdf · arXiv:2601.09625

## Known gaps in this bibliography
- No citation counts (no Scholar access). No dedicated CVE/advisory index. Multimodal, supply-chain, benchmarking sources not collected. Several elder-plinius and secondary tool pages not cross-verified against primary repos.
