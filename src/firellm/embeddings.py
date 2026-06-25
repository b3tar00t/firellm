from __future__ import annotations

from collections import Counter
from math import sqrt
from typing import Dict, Iterable, List

import re
from typing import List


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
