from __future__ import annotations

import re
from collections import Counter
from math import sqrt
from typing import Iterable, List, Sequence

# sentence-transformers is the canonical embedding path, consistent with
# attack_surface.py (all-MiniLM-L6-v2). It is imported defensively so offline
# environments without the model fall back to the deterministic token-count
# path below instead of crashing.
try:  # pragma: no cover - import guard
    from sentence_transformers import SentenceTransformer, util
except Exception:  # pragma: no cover - import guard
    SentenceTransformer = None  # type: ignore
    util = None  # type: ignore

_MODEL = None
_MODEL_FAILED = False


def get_model():
    """Load and cache the all-MiniLM-L6-v2 model, matching attack_surface.py.

    Returns None when sentence-transformers or its weights are unavailable, so
    callers fall back to the deterministic token-count path.
    """
    global _MODEL, _MODEL_FAILED
    if _MODEL is None and not _MODEL_FAILED:
        if SentenceTransformer is None:
            _MODEL_FAILED = True
            return None
        try:
            _MODEL = SentenceTransformer("all-MiniLM-L6-v2")
        except Exception:
            _MODEL_FAILED = True
            _MODEL = None
    return _MODEL


def embed_texts(texts: Sequence[str]) -> List:
    """Return a sentence-transformer embedding per text (canonical path).

    Falls back to token-count Counters when the model is unavailable so
    behavioral-delta computation still works fully offline.
    """
    model = get_model()
    if model is None:
        return embed_counts(texts)
    return [model.encode(text, convert_to_tensor=True) for text in texts]


def cosine(left, right) -> float:
    """Cosine similarity for sentence-transformer tensors or Counter fallbacks."""
    if isinstance(left, Counter) and isinstance(right, Counter):
        return cosine_from_counters(left, right)
    if util is not None:
        try:
            return float(util.cos_sim(left, right).item())
        except Exception:
            return 0.0
    return 0.0


# --- token-count helpers (deterministic, dependency-free) ---------------------
# Retained for rag_simulator.py, which is the custom local heuristic RAG sim.


def tokenize(text: str) -> List[str]:
    tokens = re.findall(r"\w+", text.lower())
    return [t for t in tokens if len(t) > 1]


def embed_counts(texts: Iterable[str]) -> List[Counter]:
    """Return token-count 'embeddings' (Counter) for each text. Deterministic and test-friendly.

    This is a lightweight, dependency-free fallback for environments where
    heavyweight models are unavailable. It can be replaced by real embeddings
    (sentence-transformers, OpenAI embeddings) by implementing the same API.
    """
    counters: List[Counter] = []
    for t in texts:
        tokens = tokenize(t)
        counters.append(Counter(tokens))
    return counters


def cosine_from_counters(a: Counter, b: Counter) -> float:
    if not a or not b:
        return 0.0
    dot = sum(a[k] * b.get(k, 0) for k in a)
    norm_a = sqrt(sum(v * v for v in a.values()))
    norm_b = sqrt(sum(v * v for v in b.values()))
    if norm_a == 0 or norm_b == 0:
        return 0.0
    return dot / (norm_a * norm_b)


def embed_and_cosine_scores(query: str, docs: List[str]) -> List[float]:
    """Embed a query and list of docs, return cosine similarity scores per doc."""
    all_texts = [query] + docs
    embs = embed_counts(all_texts)
    q_emb = embs[0]
    doc_embs = embs[1:]
    return [cosine_from_counters(q_emb, d) for d in doc_embs]
