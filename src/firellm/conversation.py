"""Multi-turn execution engine (FireLLM G1).

Drives a conversation against a target turn-by-turn, asks a pluggable *attacker*
for each next message, evaluates every target reply with ``SuccessEvaluator``, and
stops on the first confirmed objective. This is the honest execution of the
``strategy`` ``.fllm`` corpus (crescendo / skeleton_key / flip_attack / pair /
tree_of_attacks), which until now was stored but not run.

Attacker implementations:
  - ``ScriptedAttacker``   — fixed turns (the 3 direct-send scaffolds and any
    hand-written escalation); no model, fully offline, used by the regression test.
  - ``LLMAttacker``        — pluggable: the operator supplies their own model via a
    ``generate(prompt) -> str`` callable. FireLLM ships no attacker model. Renders a
    ``strategy`` scaffold (crescendo/pair/tap) each turn from the running transcript.

Authorization: an ``LLMAttacker`` driven at a non-loopback target is live offensive
traffic. ``require_authorization`` gates it — loopback targets run freely; any other
host requires an explicit operator flag and logs the target URL. The attacker's
*objective* is sourced from the payload corpus (all canary/marker based), not a
free-text CLI argument, so the engine confirms planted findings rather than
generating open-ended content.
"""
from __future__ import annotations

import json
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import urlparse

from .scoring import Scorer, ScoreResult
from .success_evaluator import EvaluationResult, SuccessEvaluator

logger = logging.getLogger("firellm.conversation")

_LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1", "0.0.0.0"}


class AuthorizationError(RuntimeError):
    """Raised when a live (non-loopback) attack runs without operator authorization."""


def is_loopback(target_url: str) -> bool:
    try:
        host = (urlparse(target_url).hostname or "").lower()
    except ValueError:
        return False
    return host in _LOOPBACK_HOSTS


def require_authorization(target_url: str, authorized: bool) -> None:
    """Permit a loopback target unconditionally; require ``authorized`` otherwise.

    Logs the target URL on every authorized live run so there is an operator-side
    record of what was attacked.
    """
    if is_loopback(target_url):
        return
    if not authorized:
        raise AuthorizationError(
            f"Refusing to run a live multi-turn attack against non-loopback target "
            f"{target_url!r} without explicit operator authorization. Re-run with the "
            f"authorization flag only against systems you are permitted to test."
        )
    logger.warning("AUTHORIZED live multi-turn attack against target: %s", target_url)


@dataclass
class ConversationTurn:
    index: int
    attacker_message: str
    target_response: str
    evaluation: EvaluationResult
    score: Optional[ScoreResult] = None


@dataclass
class ConversationResult:
    confirmed: bool
    turns_used: int
    stopped_reason: str
    objective: str
    transcript: List[ConversationTurn] = field(default_factory=list)
    confidence: float = 0.0
    explanation: str = ""

    @property
    def messages(self) -> List[Dict[str, str]]:
        msgs: List[Dict[str, str]] = []
        for t in self.transcript:
            msgs.append({"role": "user", "content": t.attacker_message})
            msgs.append({"role": "assistant", "content": t.target_response})
        return msgs


class Attacker(ABC):
    """Produces the next attacker message given the conversation so far."""

    @abstractmethod
    def next_message(
        self,
        objective: str,
        history: List[Dict[str, str]],
        last_response: Optional[str],
        turn_index: int,
        max_turns: int,
    ) -> Optional[str]:
        """Return the next user message, or ``None`` to end the conversation."""
        raise NotImplementedError


class ScriptedAttacker(Attacker):
    """Replays a fixed list of turns, one per step, ignoring target feedback.

    Covers the 3 direct-send scaffolds (skeleton_key x2, flip_attack) and any
    hand-written deterministic escalation. Offline, no model required.
    """

    def __init__(self, turns: List[str]) -> None:
        self._turns = list(turns)

    def next_message(self, objective, history, last_response, turn_index, max_turns):
        if turn_index >= len(self._turns):
            return None
        return self._turns[turn_index]


class LLMAttacker(Attacker):
    """Feedback-driven attacker backed by an operator-supplied model.

    ``generate`` is any callable the operator provides — a local Ollama call, an
    API client, etc. FireLLM bundles no model. ``scaffold`` is a ``strategy``
    ``.fllm`` turn body (crescendo / pair / tree_of_attacks) that instructs the
    model how to craft each next message; ``{{objective}}`` and friends are
    substituted here (``.fllm`` resolve leaves them as literal ``{...}``).

    The model is asked to answer as JSON ``{"next_message": ".."}``; a bare string
    reply is used verbatim as a fallback.
    """

    def __init__(
        self,
        generate: Callable[[str], str],
        scaffold: str,
        extra_vars: Optional[Dict[str, Any]] = None,
    ) -> None:
        self._generate = generate
        self._scaffold = scaffold
        self._extra = dict(extra_vars or {})

    def _render_scaffold(self, objective: str, max_turns: int, history: List[Dict[str, str]]) -> str:
        context = "\n".join(
            f"{m.get('role', 'user')}: {m.get('content', '')}" for m in history
        )
        values = {
            "objective": objective,
            "max_turns": str(max_turns),
            "conversation_context": context,
            "desired_prefix": self._extra.get("desired_prefix", "Sure, here is"),
            "prompt": self._extra.get("prompt", objective),
            **{k: str(v) for k, v in self._extra.items()},
        }
        rendered = self._scaffold
        for key, val in values.items():
            rendered = rendered.replace("{{" + key + "}}", str(val))
            rendered = rendered.replace("{{ " + key + " }}", str(val))
        return rendered

    def next_message(self, objective, history, last_response, turn_index, max_turns):
        scaffold = self._render_scaffold(objective, max_turns, history)
        instruction = (
            f"{scaffold}\n\n"
            f"Current turn: {turn_index + 1} of {max_turns}.\n"
            f"Last target response: {last_response or '(none yet)'}\n\n"
            f'Respond ONLY with JSON: {{"next_message": "<the next message to send>"}}.'
        )
        raw = self._generate(instruction)
        return self._parse(raw)

    @staticmethod
    def _parse(raw: str) -> Optional[str]:
        if raw is None:
            return None
        text = raw.strip()
        try:
            data = json.loads(text)
            if isinstance(data, dict) and isinstance(data.get("next_message"), str):
                return data["next_message"]
        except (ValueError, TypeError):
            pass
        return text or None


class ConversationManager:
    """Runs an attacker against a target turn-by-turn until confirmed or exhausted."""

    def __init__(self, evaluator: Optional[SuccessEvaluator] = None) -> None:
        self.evaluator = evaluator or SuccessEvaluator()

    def run(
        self,
        target: Any,
        attacker: Attacker,
        objective: str,
        success_criteria: List[Dict[str, Any]],
        max_turns: int = 5,
        reference: Optional[str] = None,
        provider: Optional[str] = None,
        scorer: Optional[Scorer] = None,
        target_url: Optional[str] = None,
        authorized: bool = False,
    ) -> ConversationResult:
        """Drive the conversation; stop on first confirmed objective.

        ``target`` must expose ``send_messages(messages)`` (any
        ``PromptDeliveryAdapter`` or ``HTTPAdapter``). ``objective`` is applied
        verbatim and is operator-supplied — FireLLM authors no objective.

        Confirmation fires when either the canary ``success_criteria``
        (``SuccessEvaluator``) OR the optional real-output ``scorer`` reports
        success, so a run can confirm a planted canary or a real-world objective.

        If ``target_url`` is given, ``require_authorization`` gates it: a
        non-loopback target without ``authorized=True`` raises before any traffic.
        Returns a :class:`ConversationResult` with the full transcript.
        """
        if target_url is not None:
            require_authorization(target_url, authorized)
        history: List[Dict[str, str]] = []
        transcript: List[ConversationTurn] = []
        last_response: Optional[str] = None

        for turn_index in range(max_turns):
            message = attacker.next_message(
                objective, list(history), last_response, turn_index, max_turns
            )
            if message is None:
                return ConversationResult(
                    confirmed=False,
                    turns_used=turn_index,
                    stopped_reason="attacker_exhausted",
                    objective=objective,
                    transcript=transcript,
                )
            history.append({"role": "user", "content": message})
            response = target.send_messages(history)
            history.append({"role": "assistant", "content": response})
            last_response = response

            evaluation = self.evaluator.evaluate(
                response,
                success_criteria,
                reference=reference,
                provider=provider,
                objective=objective,
            )
            score = scorer.score(response, objective) if scorer else None
            transcript.append(
                ConversationTurn(turn_index, message, response, evaluation, score)
            )
            if evaluation.matched or (score is not None and score.success):
                if evaluation.matched:
                    confidence, explanation = evaluation.confidence, evaluation.explanation
                else:
                    confidence, explanation = score.confidence, f"scorer[{score.scorer}]: {score.reason}"
                return ConversationResult(
                    confirmed=True,
                    turns_used=turn_index + 1,
                    stopped_reason="objective_confirmed",
                    objective=objective,
                    transcript=transcript,
                    confidence=confidence,
                    explanation=explanation,
                )

        return ConversationResult(
            confirmed=False,
            turns_used=max_turns,
            stopped_reason="max_turns_reached",
            objective=objective,
            transcript=transcript,
        )
