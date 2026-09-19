"""Three detectors for evaluation-set contamination, and honest scoring of them.

The intellectual content of this module is the insistence that these are three
*different kinds of evidence*, not three settings of one dial:

    level 0  byte identity        H(raw bytes)                  deterministic
    level 1  structural identity  H(canonical_eval(x))          deterministic
    level 2  lexical similarity   cos(vec(x), vec(y)) >= tau     probabilistic

Level 0 and level 1 answer "are these the same item". Level 2 answers "are
these plausibly the same item", which is a different question with a different
error profile, and it has false positives by construction. Reporting them in one
table without that distinction would be the dishonest version of this result.

Level 2 here is a char n-gram TF-IDF cosine, which is a *lexical* near-duplicate
baseline, not a semantic one. It is labelled that way everywhere it appears. A
sentence-embedding model would catch a broader paraphrase class; the hook is
``similarity_backend``, and swapping it changes only level 2's numbers, never
level 0 or 1. Do not let anyone describe level 2 as semantic in the write-up
unless an actual embedding model is behind it.

What none of the three can do: prove a model was trained on an item. All three
detect *corpus overlap*. Training exposure is a stronger claim requiring
membership inference, and the boundary belongs in the pitch.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable

from .address import addr_of, raw_byte_addr

__all__ = ["Detection", "LeakageReport", "scan", "DEFAULT_TAU"]

DEFAULT_TAU = 0.80

# Relations a planted corpus item can have to a held-out eval item. Ground
# truth for scoring; `unrelated` items are the false-positive test.
LEAK_RELATIONS = ("exact", "serialization", "structural", "paraphrase")
NON_LEAK_RELATIONS = ("unrelated",)


def _stable_bytes(obj: Any) -> bytes:
    """The bytes an artifact would have *as stored*, for the byte baseline.

    Uses the item's own serialization if it carried one (``_raw``), otherwise
    a plain json.dumps in insertion order -- i.e. exactly the accidental byte
    form that byte-hash dedup in the wild ends up comparing.
    """
    if isinstance(obj, dict) and "_raw" in obj:
        return obj["_raw"].encode("utf-8")
    # Strip bookkeeping keys first. Hashing them would mean the byte baseline
    # never matches anything -- an artificially crippled baseline, which would
    # inflate the structural gain. The baseline has to be the strongest honest
    # version of itself.
    return json.dumps(_payload(obj), ensure_ascii=False).encode("utf-8")


def _payload(obj: Any) -> Any:
    """The item without EvalSeal's own bookkeeping fields."""
    if isinstance(obj, dict):
        return {k: v for k, v in obj.items() if not k.startswith("_")}
    return obj


def _text_of(obj: Any) -> str:
    """Flatten an item to text for the lexical detector."""
    p = _payload(obj)
    if isinstance(p, str):
        return p
    parts: list[str] = []

    def walk(v: Any) -> None:
        if isinstance(v, dict):
            for k in sorted(v):
                parts.append(str(k))
                walk(v[k])
        elif isinstance(v, list):
            for x in v:
                walk(x)
        else:
            parts.append(str(v))

    walk(p)
    return " ".join(parts)


@dataclass
class Detection:
    method: str
    eval_id: str
    corpus_id: str
    relation: str        # ground-truth relation, when the corpus is labelled
    score: float | None  # similarity, for level 2
    true_leak: bool


@dataclass
class MethodScore:
    method: str
    level: str
    detected: int = 0
    missed: int = 0
    false_positives: int = 0
    # Matches on a corpus with no ground truth: reported separately, never
    # folded into recall or precision.
    unlabelled_hits: int = 0
    by_relation: dict[str, int] = field(default_factory=dict)

    @property
    def recall(self) -> float:
        total = self.detected + self.missed
        return self.detected / total if total else 0.0

    @property
    def precision(self) -> float:
        total = self.detected + self.false_positives
        return self.detected / total if total else 0.0


@dataclass
class LeakageReport:
    scores: dict[str, MethodScore]
    detections: list[Detection]
    n_eval: int
    n_corpus: int
    n_true_leaks: int
    tau: float
    backend: str

    @property
    def structural_gain(self) -> int:
        """Detections structural matching adds over byte matching.

        This is the single number the whole method stands on. If it is zero on
        real data, the structural claim is not doing any work there and the
        honest move is to say so.
        """
        return self.scores["structural"].detected - self.scores["byte"].detected

    def to_json(self) -> dict[str, Any]:
        return {
            "n_eval_items": self.n_eval,
            "n_corpus_items": self.n_corpus,
            "n_true_leaks_planted": self.n_true_leaks,
            "tau": self.tau,
            "level2_backend": self.backend,
            "structural_gain_over_byte": self.structural_gain,
            "methods": {
                m: {
                    "level": s.level,
                    "detected": s.detected,
                    "missed": s.missed,
                    "false_positives": s.false_positives,
                    "unlabelled_hits": s.unlabelled_hits,
                    "recall": round(s.recall, 4),
                    "precision": round(s.precision, 4),
                    "by_relation": s.by_relation,
                }
                for m, s in self.scores.items()
            },
        }


# --------------------------------------------------------------------------
# level 2 backend
# --------------------------------------------------------------------------

def _tfidf_backend(eval_texts: list[str], corpus_texts: list[str]):
    """Char 4-gram TF-IDF cosine. Lexical, not semantic -- see module docstring."""
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.metrics.pairwise import cosine_similarity

    vec = TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), min_df=1)
    vec.fit(eval_texts + corpus_texts)
    return cosine_similarity(vec.transform(eval_texts), vec.transform(corpus_texts))


SimilarityBackend = Callable[[list[str], list[str]], Any]


# --------------------------------------------------------------------------
# main entry point
# --------------------------------------------------------------------------

def tau_sweep(
    eval_items: list[dict[str, Any]],
    corpus_items: list[dict[str, Any]],
    taus: tuple[float, ...] = (0.50, 0.60, 0.70, 0.75, 0.80, 0.85, 0.90, 0.95),
) -> list[dict[str, Any]]:
    """Level 2 detections and false positives across thresholds.

    A single threshold invites the obvious objection that it was chosen after
    seeing the results. Reporting the curve removes the question: the reader can
    see where the probabilistic method starts trading precision for recall, and
    that the deterministic rows do not move at all.
    """
    import copy

    rows = []
    for t in taus:
        r = scan(copy.deepcopy(eval_items), copy.deepcopy(corpus_items), tau=t)
        s = r.scores["lexical"]
        rows.append(
            {
                "tau": t,
                "detected": s.detected,
                "false_positives": s.false_positives,
                "missed": s.missed,
                "recall": round(s.recall, 4),
                "precision": round(s.precision, 4),
            }
        )
    return rows


def scan(
    eval_items: Iterable[dict[str, Any]],
    corpus_items: Iterable[dict[str, Any]],
    tau: float = DEFAULT_TAU,
    similarity_backend: SimilarityBackend | None = None,
    backend_name: str = "char-ngram-tfidf (lexical)",
) -> LeakageReport:
    """Run all three detectors over eval x corpus and score them.

    Items may carry ``_id``, ``_raw`` (original serialization) and ``_relation``
    /``_leak_of`` (ground truth, when the corpus was generated by ``mutate.py``).
    Unlabelled corpora are scanned fine; the scoring columns are then just
    detection counts with no recall.
    """
    ev = list(eval_items)
    co = list(corpus_items)

    for i, it in enumerate(ev):
        it.setdefault("_id", f"eval-{i:03d}")
    for i, it in enumerate(co):
        it.setdefault("_id", f"corpus-{i:03d}")

    # Level 0: byte identity over the stored serialization.
    byte_index: dict[str, list[dict]] = {}
    for it in co:
        byte_index.setdefault(raw_byte_addr(_stable_bytes(it)), []).append(it)

    # Level 1: structural identity under the *eval* profile.
    struct_index: dict[str, list[dict]] = {}
    for it in co:
        struct_index.setdefault(addr_of(_payload(it), "eval"), []).append(it)

    scores = {
        "byte": MethodScore("byte", "level 0 - byte identity"),
        "structural": MethodScore("structural", "level 1 - structural identity"),
        "lexical": MethodScore("lexical", "level 2 - lexical similarity"),
    }
    detections: list[Detection] = []

    # Ground truth: which eval ids each corpus item was planted from.
    truth: dict[str, set[str]] = {}
    for it in co:
        rel = it.get("_relation")
        if rel in LEAK_RELATIONS and it.get("_leak_of"):
            truth.setdefault(it["_leak_of"], set()).add(it["_id"])
    n_true_leaks = sum(len(v) for v in truth.values())

    def record(method: str, e: dict, c: dict, score: float | None) -> None:
        rel = c.get("_relation", "unlabelled")
        true_leak = rel in LEAK_RELATIONS and c.get("_leak_of") == e["_id"]
        detections.append(Detection(method, e["_id"], c["_id"], rel, score, true_leak))
        s = scores[method]
        if true_leak:
            s.detected += 1
            s.by_relation[rel] = s.by_relation.get(rel, 0) + 1
        elif rel == "unlabelled":
            # No ground truth for this corpus, so the match is neither a
            # confirmed detection nor a confirmed false positive. Counting it as
            # a detection made recall and precision rise toward 1 purely from
            # unlabelled noise -- a number manufactured from nothing.
            s.unlabelled_hits += 1
        else:
            s.false_positives += 1
            s.by_relation[f"FP:{rel}"] = s.by_relation.get(f"FP:{rel}", 0) + 1

    for e in ev:
        for c in byte_index.get(raw_byte_addr(_stable_bytes(e)), []):
            record("byte", e, c, None)
        for c in struct_index.get(addr_of(_payload(e), "eval"), []):
            record("structural", e, c, None)

    backend = similarity_backend or _tfidf_backend
    if ev and co:
        sim = backend([_text_of(x) for x in ev], [_text_of(x) for x in co])
        for i, e in enumerate(ev):
            for j, c in enumerate(co):
                s = float(sim[i][j])
                if s >= tau:
                    record("lexical", e, c, round(s, 4))

    # Misses: a planted leak no detection of that method covered.
    for method, sc in scores.items():
        found = {(d.eval_id, d.corpus_id) for d in detections if d.method == method and d.true_leak}
        expected = {(eid, cid) for eid, cids in truth.items() for cid in cids}
        sc.missed = len(expected - found)

    return LeakageReport(
        scores=scores,
        detections=detections,
        n_eval=len(ev),
        n_corpus=len(co),
        n_true_leaks=n_true_leaks,
        tau=tau,
        backend=backend_name,
    )
