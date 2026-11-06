"""Objective-driven strategy selection (FireLLM G1).

Given an operator objective (and optionally a detected provider), rank the
available multi-turn strategies / jailbreak techniques so the engine can pick the
most promising one automatically instead of the operator naming it by hand.

Deterministic, explainable heuristics only — every score carries a reason string.
No model call. The objective is operator-supplied and never authored here; the
selector only reads it to route.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Optional

from .payload_loader import PayloadItem

# Reasoning-model providers where H-CoT / CoT-hijacking applies.
_REASONING_HINTS = re.compile(
    r"\b(o1|o3|o4|r1|deepseek|thinking|reason|qwq|grok.?thinking)\b", re.I
)

# Baseline technique priors (robustness/generality), higher = try earlier.
_TECHNIQUE_PRIOR = {
    "crescendo": 0.9,
    "deceptive_delight": 0.85,
    "bad_likert_judge": 0.8,
    "pair": 0.7,
    "tree_of_attacks": 0.7,
    "skeleton_key": 0.65,
    "h_cot": 0.6,
    "deepinception": 0.55,
    "fallacy_failure": 0.5,
    "flip_attack": 0.45,
}

# Objective-keyword -> techniques that suit it, with a boost.
_OBJECTIVE_ROUTES = [
    (re.compile(r"system prompt|instruction|initial prompt|your role", re.I),
     {"deceptive_delight": 0.3, "bad_likert_judge": 0.3, "crescendo": 0.2},
     "objective targets system-prompt leakage; elicitation strategies favored"),
    (re.compile(r"credential|api.?key|password|secret|token|\bpii\b|personal data", re.I),
     {"bad_likert_judge": 0.3, "deceptive_delight": 0.25},
     "objective targets sensitive-data disclosure; judge/interleave strategies favored"),
    (re.compile(r"knowledge base|document|corpus|retriev|\brag\b", re.I),
     {"crescendo": 0.3, "deceptive_delight": 0.2},
     "objective targets knowledge-base enumeration; gradual-escalation favored"),
    (re.compile(r"tool|function|agent|email|api call|execute|invoke", re.I),
     {"crescendo": 0.25, "pair": 0.2},
     "objective targets tool/agent misuse; iterative strategies favored"),
]


@dataclass
class StrategyChoice:
    item: PayloadItem
    score: float
    reasons: List[str]


def select_strategies(
    objective: str,
    items: List[PayloadItem],
    provider: Optional[str] = None,
    top_k: Optional[int] = None,
) -> List[StrategyChoice]:
    """Rank ``items`` for ``objective`` (and optional ``provider``), best first.

    ``items`` may mix ``strategy`` and single-turn ``payload`` techniques; both are
    rankable. Ties break on technique name for determinism.
    """
    obj = objective or ""
    reasoning_target = bool(provider and _REASONING_HINTS.search(provider))

    choices: List[StrategyChoice] = []
    for item in items:
        tech = (item.technique or "").lower()
        reasons: List[str] = []
        score = _TECHNIQUE_PRIOR.get(tech, 0.4)
        reasons.append(f"base prior {score:.2f} for technique '{tech}'")

        for pattern, boosts, why in _OBJECTIVE_ROUTES:
            if pattern.search(obj) and tech in boosts:
                score += boosts[tech]
                reasons.append(f"+{boosts[tech]:.2f}: {why}")

        if reasoning_target:
            if tech == "h_cot":
                score += 0.5
                reasons.append(f"+0.50: reasoning-model provider '{provider}' — H-CoT applies")
            elif tech in ("crescendo", "deceptive_delight"):
                score += 0.05
                reasons.append("+0.05: still viable on a reasoning-model target")

        choices.append(StrategyChoice(item, round(score, 3), reasons))

    choices.sort(key=lambda c: (-c.score, (c.item.technique or "")))
    return choices[:top_k] if top_k else choices
